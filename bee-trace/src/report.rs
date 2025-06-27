use std::{collections::HashMap, fs::File, io::Write, path::Path};

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::{ReportEvent, SecurityEvent, SecurityReport};

pub struct ReportGenerator {
    report: SecurityReport,
    start_time: DateTime<Utc>,
}

impl ReportGenerator {
    pub fn new(probe_type: String) -> Self {
        let start_time = Utc::now();
        Self {
            report: SecurityReport::new(probe_type, 0),
            start_time,
        }
    }

    pub fn add_security_event(&mut self, event: &SecurityEvent) {
        let report_event = self.convert_security_event(event);
        self.report.add_event(report_event);
    }

    pub fn finalize(&mut self) -> &SecurityReport {
        let duration = Utc::now()
            .signed_duration_since(self.start_time)
            .num_seconds() as u64;
        self.report.metadata.duration_seconds = duration;
        &self.report
    }

    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json_content = self.report.to_json()?;
        let mut file = File::create(path)?;
        file.write_all(json_content.as_bytes())?;
        Ok(())
    }

    pub fn save_markdown(&self, path: &Path) -> Result<()> {
        let md_content = self.report.to_markdown();
        let mut file = File::create(path)?;
        file.write_all(md_content.as_bytes())?;
        Ok(())
    }

    pub fn print_summary(&self) {
        println!("\n📊 Security Monitoring Summary");
        println!("===============================");
        println!(
            "Duration: {} seconds",
            self.report.metadata.duration_seconds
        );
        println!("Total Events: {}", self.report.metadata.total_events);
        println!("File Access: {}", self.report.summary.file_events);
        println!("Network Activity: {}", self.report.summary.network_events);
        println!(
            "Secret Access: {}",
            self.report.summary.secret_access_events
        );
        println!("Memory Access: {}", self.report.summary.memory_events);

        if self.report.summary.high_severity_events > 0 {
            println!(
                "⚠️  High Severity Events: {}",
                self.report.summary.high_severity_events
            );
        } else {
            println!("✅ No high severity events detected");
        }
    }

    pub fn get_stats(&self) -> ReportStats {
        let mut process_stats = HashMap::new();
        let mut severity_breakdown = HashMap::new();
        let mut event_type_breakdown = HashMap::new();

        for event in &self.report.events {
            *process_stats.entry(event.command.clone()).or_insert(0) += 1;
            *severity_breakdown
                .entry(event.severity.clone())
                .or_insert(0) += 1;
            *event_type_breakdown
                .entry(event.event_type.clone())
                .or_insert(0) += 1;
        }

        ReportStats {
            total_events: self.report.metadata.total_events,
            duration_seconds: self.report.metadata.duration_seconds,
            process_stats,
            severity_breakdown,
            event_type_breakdown,
        }
    }

    fn convert_security_event(&self, event: &SecurityEvent) -> ReportEvent {
        let timestamp = Utc::now().to_rfc3339();
        let pid = event.pid();
        let command = event.command_as_str();

        match event {
            SecurityEvent::Network(e) => ReportEvent {
                timestamp,
                event_type: "NETWORK".to_string(),
                severity: self.classify_network_severity(e.dest_ip_as_str(), e.dest_port),
                pid,
                uid: e.uid,
                command,
                details: format!(
                    "{}:{} ({})",
                    e.dest_ip_as_str(),
                    e.dest_port,
                    e.protocol_as_str()
                ),
            },
            SecurityEvent::SecretAccess(e) => {
                let event_type = if e.access_type == 0 {
                    "SECRET_FILE"
                } else {
                    "SECRET_ENV"
                };
                ReportEvent {
                    timestamp,
                    event_type: event_type.to_string(),
                    severity: "high".to_string(),
                    pid,
                    uid: e.uid,
                    command,
                    details: e.path_or_var_as_str().to_string(),
                }
            }
            SecurityEvent::ProcessMemory(e) => ReportEvent {
                timestamp,
                event_type: "PROC_MEMORY".to_string(),
                severity: "high".to_string(),
                pid,
                uid: e.uid,
                command,
                details: format!(
                    "target_pid:{} ({})",
                    e.target_pid,
                    if e.syscall_type == 0 {
                        "ptrace"
                    } else {
                        "process_vm_readv"
                    }
                ),
            },
        }
    }

    fn classify_network_severity(&self, dest_ip: &str, port: u16) -> String {
        let suspicious_ports = [22, 23, 3389, 5900, 6000];
        let common_safe_ports = [80, 443, 53, 993, 995, 587, 465];

        if suspicious_ports.contains(&port) {
            return "high".to_string();
        }

        if dest_ip.starts_with("127.")
            || dest_ip.starts_with("10.")
            || dest_ip.starts_with("192.168.")
            || dest_ip.starts_with("172.")
        {
            return "low".to_string();
        }

        if common_safe_ports.contains(&port) {
            return "medium".to_string();
        }

        "medium".to_string()
    }
}

pub struct ReportStats {
    pub total_events: u64,
    pub duration_seconds: u64,
    pub process_stats: HashMap<String, u64>,
    pub severity_breakdown: HashMap<String, u64>,
    pub event_type_breakdown: HashMap<String, u64>,
}

impl ReportStats {
    pub fn print_detailed(&self) {
        println!("\n📈 Detailed Statistics");
        println!("======================");

        println!("\n🔢 Event Types:");
        for (event_type, count) in &self.event_type_breakdown {
            println!("  {}: {}", event_type, count);
        }

        println!("\n⚡ Severity Breakdown:");
        for (severity, count) in &self.severity_breakdown {
            let icon = match severity.as_str() {
                "high" | "critical" => "🔴",
                "medium" => "🟡",
                _ => "🟢",
            };
            println!("  {} {}: {}", icon, severity, count);
        }

        println!("\n💻 Top Processes:");
        let mut sorted_processes: Vec<_> = self.process_stats.iter().collect();
        sorted_processes.sort_by(|a, b| b.1.cmp(a.1));

        for (process, count) in sorted_processes.iter().take(10) {
            println!("  {}: {}", process, count);
        }

        if self.duration_seconds > 0 {
            let events_per_second = self.total_events as f64 / self.duration_seconds as f64;
            println!("\n📊 Rate: {:.2} events/second", events_per_second);
        }
    }
}

#[cfg(test)]
mod tests {
    use bee_trace_common::SecretAccessEvent;

    use super::*;

    #[test]
    fn should_create_new_report_generator() {
        let generator = ReportGenerator::new("test".to_string());
        assert_eq!(generator.report.metadata.probe_type, "test");
        assert_eq!(generator.report.metadata.total_events, 0);
    }

    #[test]
    fn should_classify_network_severity() {
        let generator = ReportGenerator::new("test".to_string());

        assert_eq!(
            generator.classify_network_severity("192.168.1.1", 22),
            "high"
        );
        assert_eq!(generator.classify_network_severity("8.8.8.8", 22), "high");
        assert_eq!(generator.classify_network_severity("127.0.0.1", 80), "low");
        assert_eq!(
            generator.classify_network_severity("8.8.8.8", 443),
            "medium"
        );
    }

    #[test]
    fn should_add_and_track_events() {
        let mut generator = ReportGenerator::new("test".to_string());

        let secret_event = SecretAccessEvent::new()
            .with_pid(1234)
            .with_uid(1000)
            .with_command(b"cat")
            .with_file_access(b"/etc/passwd");

        generator.add_security_event(&SecurityEvent::SecretAccess(secret_event));

        assert_eq!(generator.report.metadata.total_events, 1);
        assert_eq!(generator.report.summary.secret_access_events, 1);
    }

    #[test]
    fn should_calculate_stats() {
        let mut generator = ReportGenerator::new("test".to_string());

        let secret_event = SecretAccessEvent::new()
            .with_command(b"cat")
            .with_file_access(b"/etc/passwd");

        generator.add_security_event(&SecurityEvent::SecretAccess(secret_event));

        let stats = generator.get_stats();
        assert_eq!(stats.total_events, 1);
        assert_eq!(stats.process_stats.get("cat").unwrap(), &1);
        assert_eq!(stats.event_type_breakdown.get("SECRET_FILE").unwrap(), &1);
    }
}
