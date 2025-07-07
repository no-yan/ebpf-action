use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::configuration::Configuration;

#[derive(Parser)]
#[command(name = "bee-trace")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "bee-trace contributors")]
#[command(about = "eBPF-based security monitoring and tracing tool")]
#[command(
    long_about = "bee-trace uses eBPF to monitor system activities including file access, network connections, memory operations, and secret access attempts."
)]
pub struct CliApp {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub args: CliArgs,
}

#[derive(Parser)]
pub struct CliArgs {
    /// Type of probe to attach
    #[arg(short = 'p', long, value_enum, default_value = "file-monitor")]
    #[arg(help = "Specify which eBPF probe to attach")]
    pub probe_type: ProbeType,

    /// Duration to run the tracer in seconds
    #[arg(short = 'd', long)]
    #[arg(
        help = "Specify how long to run the monitoring session. If not specified, runs until Ctrl+C is pressed."
    )]
    pub duration: Option<u64>,

    /// Filter events by process name (substring match)
    #[arg(short = 'c', long)]
    #[arg(help = "Only show events from processes whose command name contains this pattern.")]
    pub command: Option<String>,

    /// Show verbose output including UIDs
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Enable security monitoring mode with enhanced event classification
    #[arg(long)]
    pub security_mode: bool,

    /// Configuration file path
    #[arg(long)]
    #[arg(help = "Path to YAML configuration file for advanced settings.")]
    pub config: Option<PathBuf>,

    /// Output file for saving results
    #[arg(short = 'o', long)]
    #[arg(
        help = "Save monitoring results to a file. Supports JSON and Markdown formats based on file extension."
    )]
    pub output: Option<PathBuf>,

    /// Output format
    #[arg(short = 'f', long, value_enum, default_value = "json")]
    #[arg(help = "Format for saved output: json, markdown, or csv")]
    pub format: OutputFormat,

    /// Only show events of specified severity or higher
    #[arg(long, value_enum)]
    pub filter_severity: Option<SeverityLevel>,

    /// Suppress column headers in output
    #[arg(long)]
    pub no_header: bool,

    /// Timestamp format for events
    #[arg(long, value_enum, default_value = "iso8601")]
    pub timestamp_format: TimestampFormat,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProbeType {
    #[value(name = "file_monitor")]
    FileMonitor,
    #[value(name = "network_monitor")]
    NetworkMonitor,
    #[value(name = "memory_monitor")]
    MemoryMonitor,
    #[value(name = "all")]
    All,
}

impl From<ProbeType> for Vec<crate::errors::ProbeType> {
    fn from(cli_type: ProbeType) -> Self {
        match cli_type {
            ProbeType::FileMonitor => vec![crate::errors::ProbeType::FileMonitor],
            ProbeType::NetworkMonitor => vec![crate::errors::ProbeType::NetworkMonitor],
            ProbeType::MemoryMonitor => vec![crate::errors::ProbeType::MemoryMonitor],
            ProbeType::All => crate::errors::ProbeType::all(),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    #[value(name = "json")]
    Json,
    #[value(name = "markdown")]
    Markdown,
    #[value(name = "csv")]
    Csv,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum SeverityLevel {
    #[value(name = "low")]
    Low,
    #[value(name = "medium")]
    Medium,
    #[value(name = "high")]
    High,
    #[value(name = "critical")]
    Critical,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum TimestampFormat {
    #[value(name = "unix")]
    Unix,
    #[value(name = "iso8601")]
    Iso8601,
    #[value(name = "relative")]
    Relative,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate reports from saved monitoring data
    Report {
        /// Input file containing monitoring data
        input: PathBuf,
        /// Report format
        #[arg(short = 'f', long, value_enum, default_value = "summary")]
        format: ReportFormat,
        /// Output file for the report
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Generate a sample configuration file
    Generate {
        /// Output configuration file path
        #[arg(short = 'o', long, default_value = "bee-trace.yaml")]
        output: PathBuf,
    },
    /// Validate a configuration file
    Validate {
        /// Configuration file to validate
        config: PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ReportFormat {
    #[value(name = "summary")]
    Summary,
    #[value(name = "detailed")]
    Detailed,
    #[value(name = "json")]
    Json,
    #[value(name = "markdown")]
    Markdown,
}

impl CliArgs {
    pub fn should_show_severity(&self, severity: &SeverityLevel) -> bool {
        if let Some(min_severity) = &self.filter_severity {
            let severity_levels = [
                SeverityLevel::Low,
                SeverityLevel::Medium,
                SeverityLevel::High,
                SeverityLevel::Critical,
            ];
            let min_index = severity_levels
                .iter()
                .position(|s| s == min_severity)
                .unwrap_or(0);
            let event_index = severity_levels
                .iter()
                .position(|s| s == severity)
                .unwrap_or(0);
            return event_index >= min_index;
        }
        true
    }
}

/// Create configuration directly from CLI arguments
pub fn create_configuration_from_cli_args(args: &CliArgs) -> Result<Configuration, anyhow::Error> {
    crate::configuration::ConfigurationBuilder::new()
        .from_cli_args_typed(args)
        .map_err(|e| anyhow::anyhow!("Failed to parse CLI arguments: {}", e))?
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build configuration: {}", e))
}

pub fn print_banner() {
    println!("🐝 bee-trace v{}", env!("CARGO_PKG_VERSION"));
    println!("eBPF-based Security Monitoring Tool");
    println!("====================================");
}

pub fn print_usage_examples() {
    println!("\nExamples:");
    println!("  # Monitor file access and security events");
    println!("  bee-trace");
    println!();
    println!("  # Monitor all security events for 60 seconds");
    println!("  bee-trace --probe-type all --duration 60 --security-mode");
    println!();
    println!("  # Monitor network connections with verbose output");
    println!("  bee-trace --probe-type network_monitor --verbose");
    println!();
    println!("  # Filter events from specific process and save to file");
    println!("  bee-trace --command \"nginx\" --output report.json");
    println!();
    println!("  # Generate configuration file");
    println!("  bee-trace config generate --output my-config.yaml");
    println!();
    println!("  # Generate report from saved data");
    println!("  bee-trace report monitoring-data.json --format markdown");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn should_parse_basic_args() {
        let args =
            CliApp::try_parse_from(vec!["bee-trace", "--probe-type", "file_monitor"]).unwrap();
        assert!(matches!(args.args.probe_type, ProbeType::FileMonitor));
        assert!(!args.args.verbose);
        assert!(!args.args.security_mode);
    }

    #[test]
    fn should_parse_complex_args() {
        let args = CliApp::try_parse_from(vec![
            "bee-trace",
            "--probe-type",
            "network_monitor",
            "--duration",
            "30",
            "--command",
            "nginx",
            "--verbose",
            "--security-mode",
        ])
        .unwrap();

        assert!(matches!(args.args.probe_type, ProbeType::NetworkMonitor));
        assert_eq!(args.args.duration, Some(30));
        assert_eq!(args.args.command, Some("nginx".to_string()));
        assert!(args.args.verbose);
        assert!(args.args.security_mode);
    }

    #[test]
    fn should_filter_severity_correctly() {
        let args = CliArgs {
            probe_type: ProbeType::FileMonitor,
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
            output: None,
            format: OutputFormat::Json,
            filter_severity: Some(SeverityLevel::Medium),
            no_header: false,
            timestamp_format: TimestampFormat::Iso8601,
        };

        assert!(!args.should_show_severity(&SeverityLevel::Low));
        assert!(args.should_show_severity(&SeverityLevel::Medium));
        assert!(args.should_show_severity(&SeverityLevel::High));
        assert!(args.should_show_severity(&SeverityLevel::Critical));
    }

    #[test]
    fn should_create_configuration_from_cli_args() {
        let args = CliArgs {
            probe_type: ProbeType::All,
            duration: Some(60),
            command: Some("test".to_string()),
            verbose: true,
            security_mode: true,
            config: None,
            output: None,
            format: OutputFormat::Json,
            filter_severity: None,
            no_header: false,
            timestamp_format: TimestampFormat::Iso8601,
        };

        let config = create_configuration_from_cli_args(&args).unwrap();
        assert_eq!(config.duration_secs(), Some(60));
        assert_eq!(config.command_filter(), Some("test"));
        assert!(config.is_verbose());
        assert!(config.is_security_mode());
    }
}
