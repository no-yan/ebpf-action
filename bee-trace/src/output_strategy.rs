use crate::security_classifier::SecurityClassification;
use crate::{Formattable, SecurityEvent};
use anyhow::Result;
use serde_json;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub trait OutputStrategy {
    fn format_event(
        &self,
        event: &SecurityEvent,
        classification: &SecurityClassification,
    ) -> String;
    fn format_header(&self) -> String;
    fn format_summary(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> String;
    fn save_to_file(&self, path: &Path, content: &str) -> Result<()>;
}

pub struct JsonOutputStrategy;

impl OutputStrategy for JsonOutputStrategy {
    fn format_event(
        &self,
        event: &SecurityEvent,
        classification: &SecurityClassification,
    ) -> String {
        let json_event = JsonEventOutput {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: event.event_type().to_string(),
            pid: event.pid(),
            uid: event.uid(),
            command: event.command(),
            details: event.details(),
            severity: classification.severity.as_str().to_string(),
            category: classification.category.clone(),
            description: classification.description.clone(),
            risk_score: classification.risk_score,
        };

        serde_json::to_string(&json_event).unwrap_or_else(|_| "{}".to_string())
    }

    fn format_header(&self) -> String {
        "".to_string() // JSON doesn't need headers
    }

    fn format_summary(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> String {
        let summary = JsonSummary {
            total_events: events.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity_breakdown: self.count_by_severity(classifications),
            event_type_breakdown: self.count_by_event_type(events),
        };

        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
    }

    fn save_to_file(&self, path: &Path, content: &str) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

impl JsonOutputStrategy {
    fn count_by_severity(
        &self,
        classifications: &[SecurityClassification],
    ) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for classification in classifications {
            let severity = classification.severity.as_str().to_string();
            *counts.entry(severity).or_insert(0) += 1;
        }
        counts
    }

    fn count_by_event_type(&self, events: &[SecurityEvent]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for event in events {
            let event_type = event.event_type().to_string();
            *counts.entry(event_type).or_insert(0) += 1;
        }
        counts
    }
}

pub struct CsvOutputStrategy;

impl OutputStrategy for CsvOutputStrategy {
    fn format_event(
        &self,
        event: &SecurityEvent,
        classification: &SecurityClassification,
    ) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{}",
            chrono::Utc::now().to_rfc3339(),
            event.event_type(),
            event.pid(),
            event.uid(),
            escape_csv(&event.command()),
            escape_csv(&event.details()),
            classification.severity.as_str(),
            escape_csv(&classification.category),
            classification.risk_score
        )
    }

    fn format_header(&self) -> String {
        "timestamp,event_type,pid,uid,command,details,severity,category,risk_score".to_string()
    }

    fn format_summary(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> String {
        let mut summary = String::new();
        writeln!(&mut summary, "# Security Event Summary").unwrap();
        writeln!(&mut summary, "Total Events: {}", events.len()).unwrap();
        writeln!(
            &mut summary,
            "Timestamp: {}",
            chrono::Utc::now().to_rfc3339()
        )
        .unwrap();

        // Severity breakdown
        let mut severity_counts = HashMap::new();
        for classification in classifications {
            *severity_counts
                .entry(classification.severity.as_str())
                .or_insert(0) += 1;
        }

        writeln!(&mut summary, "\n# Severity Breakdown").unwrap();
        for (severity, count) in severity_counts {
            writeln!(&mut summary, "{}: {}", severity, count).unwrap();
        }

        summary
    }

    fn save_to_file(&self, path: &Path, content: &str) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

pub struct PlainTextOutputStrategy {
    verbose: bool,
}

impl PlainTextOutputStrategy {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl OutputStrategy for PlainTextOutputStrategy {
    fn format_event(
        &self,
        event: &SecurityEvent,
        classification: &SecurityClassification,
    ) -> String {
        let timestamp = chrono::Utc::now().format("%H:%M:%S").to_string();
        let severity_icon = match classification.severity.as_str() {
            "critical" => "🔴",
            "high" => "🟠",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪",
        };

        if self.verbose {
            format!(
                "[{}] {} {} [{}] PID:{} UID:{} CMD:{} - {} (Risk: {})",
                timestamp,
                severity_icon,
                classification.severity.as_str().to_uppercase(),
                event.event_type(),
                event.pid(),
                event.uid(),
                event.command(),
                event.details(),
                classification.risk_score
            )
        } else {
            format!(
                "[{}] {} {} PID:{} {} - {}",
                timestamp,
                severity_icon,
                classification.severity.as_str().to_uppercase(),
                event.pid(),
                event.command(),
                event.details()
            )
        }
    }

    fn format_header(&self) -> String {
        if self.verbose {
            "🔍 eBPF Security Monitor - Verbose Mode".to_string()
        } else {
            "🔍 eBPF Security Monitor".to_string()
        }
    }

    fn format_summary(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> String {
        let mut summary = String::new();
        writeln!(&mut summary, "\n📊 Security Event Summary").unwrap();
        writeln!(&mut summary, "=========================").unwrap();
        writeln!(&mut summary, "Total Events: {}", events.len()).unwrap();

        // Count by severity
        let mut severity_counts = HashMap::new();
        for classification in classifications {
            *severity_counts
                .entry(classification.severity.as_str())
                .or_insert(0) += 1;
        }

        writeln!(&mut summary, "\n🚨 Severity Breakdown:").unwrap();
        for (severity, count) in &severity_counts {
            let icon = match *severity {
                "critical" => "🔴",
                "high" => "🟠",
                "medium" => "🟡",
                "low" => "🟢",
                _ => "⚪",
            };
            writeln!(
                &mut summary,
                "  {} {}: {}",
                icon,
                severity.to_uppercase(),
                count
            )
            .unwrap();
        }

        // Count by event type
        let mut event_type_counts = HashMap::new();
        for event in events {
            *event_type_counts.entry(event.event_type()).or_insert(0) += 1;
        }

        writeln!(&mut summary, "\n📋 Event Types:").unwrap();
        for (event_type, count) in &event_type_counts {
            writeln!(&mut summary, "  {}: {}", event_type, count).unwrap();
        }

        // High-risk events summary
        let high_risk_events: Vec<_> = classifications
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c.severity.as_str(), "high" | "critical"))
            .collect();

        if !high_risk_events.is_empty() {
            writeln!(&mut summary, "\n⚠️  High Risk Events:").unwrap();
            for (i, classification) in high_risk_events.iter().take(5) {
                let event = &events[*i];
                writeln!(
                    &mut summary,
                    "  • {} - {} (Risk: {})",
                    classification.category,
                    event.details(),
                    classification.risk_score
                )
                .unwrap();
            }

            if high_risk_events.len() > 5 {
                writeln!(
                    &mut summary,
                    "  ... and {} more high-risk events",
                    high_risk_events.len() - 5
                )
                .unwrap();
            }
        }

        summary
    }

    fn save_to_file(&self, path: &Path, content: &str) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct JsonEventOutput {
    timestamp: String,
    event_type: String,
    pid: u32,
    uid: u32,
    command: String,
    details: String,
    severity: String,
    category: String,
    description: String,
    risk_score: u8,
}

#[derive(serde::Serialize)]
struct JsonSummary {
    total_events: usize,
    timestamp: String,
    severity_breakdown: HashMap<String, usize>,
    event_type_breakdown: HashMap<String, usize>,
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

pub struct OutputContext<S: OutputStrategy> {
    strategy: S,
}

impl<S: OutputStrategy> OutputContext<S> {
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }

    pub fn process_events(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> Vec<String> {
        events
            .iter()
            .zip(classifications.iter())
            .map(|(event, classification)| self.strategy.format_event(event, classification))
            .collect()
    }

    pub fn generate_report(
        &self,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> String {
        let mut report = String::new();

        let header = self.strategy.format_header();
        if !header.is_empty() {
            report.push_str(&header);
            report.push('\n');
        }

        for (event, classification) in events.iter().zip(classifications.iter()) {
            report.push_str(&self.strategy.format_event(event, classification));
            report.push('\n');
        }

        report.push_str(&self.strategy.format_summary(events, classifications));
        report
    }

    pub fn save_report(
        &self,
        path: &Path,
        events: &[SecurityEvent],
        classifications: &[SecurityClassification],
    ) -> Result<()> {
        let report = self.generate_report(events, classifications);
        self.strategy.save_to_file(path, &report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_classifier::{SecurityClassification, SeverityLevel};
    use bee_trace_common::{NetworkEvent, SecurityEventBuilder};
    use tempfile::NamedTempFile;

    fn create_test_event() -> SecurityEvent {
        let network_event = NetworkEvent::new().with_pid(1234).with_command(b"curl");
        SecurityEvent::Network(network_event)
    }

    fn create_test_classification() -> SecurityClassification {
        SecurityClassification {
            severity: SeverityLevel::High,
            category: "Test Category".to_string(),
            description: "Test Description".to_string(),
            risk_score: 75,
        }
    }

    #[test]
    fn should_format_json_output() {
        let strategy = JsonOutputStrategy;
        let event = create_test_event();
        let classification = create_test_classification();

        let output = strategy.format_event(&event, &classification);

        assert!(output.contains("\"event_type\":\"NETWORK\""));
        assert!(output.contains("\"pid\":1234"));
        assert!(output.contains("\"severity\":\"high\""));
        assert!(output.contains("\"risk_score\":75"));
    }

    #[test]
    fn should_format_csv_output() {
        let strategy = CsvOutputStrategy;
        let event = create_test_event();
        let classification = create_test_classification();

        let output = strategy.format_event(&event, &classification);

        assert!(output.contains("NETWORK"));
        assert!(output.contains("1234"));
        assert!(output.contains("high"));
        assert!(output.contains("75"));
    }

    #[test]
    fn should_format_plain_text_output() {
        let strategy = PlainTextOutputStrategy::new(false);
        let event = create_test_event();
        let classification = create_test_classification();

        let output = strategy.format_event(&event, &classification);

        assert!(output.contains("HIGH"));
        assert!(output.contains("PID:1234"));
        assert!(output.contains("🟠")); // High severity icon
    }

    #[test]
    fn should_generate_complete_report() {
        let strategy = PlainTextOutputStrategy::new(false);
        let context = OutputContext::new(strategy);

        let events = vec![create_test_event()];
        let classifications = vec![create_test_classification()];

        let report = context.generate_report(&events, &classifications);

        assert!(report.contains("Security Monitor"));
        assert!(report.contains("Security Event Summary"));
        assert!(report.contains("Total Events: 1"));
        assert!(report.contains("HIGH: 1"));
    }

    #[test]
    fn should_save_report_to_file() -> Result<()> {
        let strategy = JsonOutputStrategy;
        let context = OutputContext::new(strategy);

        let events = vec![create_test_event()];
        let classifications = vec![create_test_classification()];

        let temp_file = NamedTempFile::new()?;
        context.save_report(temp_file.path(), &events, &classifications)?;

        let content = std::fs::read_to_string(temp_file.path())?;
        assert!(content.contains("NETWORK"));
        assert!(content.contains("total_events"));

        Ok(())
    }

    #[test]
    fn should_escape_csv_values_correctly() {
        assert_eq!(escape_csv("simple"), "simple");
        assert_eq!(escape_csv("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(escape_csv("with\nnewline"), "\"with\nnewline\"");
    }
}
