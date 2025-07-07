use std::{path::PathBuf, time::Duration};

use clap::{Arg, ArgMatches, Command};

use crate::configuration::Configuration;

pub struct CliApp {
    app: Command,
}

impl CliApp {
    pub fn new() -> Self {
        let app = Command::new("bee-trace")
            .version(env!("CARGO_PKG_VERSION"))
            .author("bee-trace contributors")
            .about("eBPF-based security monitoring and tracing tool")
            .long_about("bee-trace uses eBPF to monitor system activities including file access, network connections, memory operations, and secret access attempts.")
            .arg(
                Arg::new("probe-type")
                    .short('p')
                    .long("probe-type")
                    .value_name("TYPE")
                    .help("Type of probe to attach")
                    .long_help("Specify which eBPF probe to attach:\n\
                               - file_monitor: Monitor file access and secret files\n\
                               - network_monitor: Monitor network connections\n\
                               - memory_monitor: Monitor process memory access\n\
                               - all: Enable all monitoring capabilities")
                    .value_parser(["file_monitor", "network_monitor", "memory_monitor", "all"])
                    .default_value("file_monitor")
            )
            .arg(
                Arg::new("duration")
                    .short('d')
                    .long("duration")
                    .value_name("SECONDS")
                    .help("Duration to run the tracer in seconds")
                    .long_help("Specify how long to run the monitoring session. If not specified, runs until Ctrl+C is pressed.")
                    .value_parser(clap::value_parser!(u64))
            )
            .arg(
                Arg::new("command")
                    .short('c')
                    .long("command")
                    .value_name("PATTERN")
                    .help("Filter events by process name (substring match)")
                    .long_help("Only show events from processes whose command name contains this pattern.")
            )
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .help("Show verbose output including UIDs")
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("security-mode")
                    .long("security-mode")
                    .help("Enable security monitoring mode with enhanced event classification")
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("config")
                    .long("config")
                    .value_name("FILE")
                    .help("Configuration file path")
                    .long_help("Path to YAML configuration file for advanced settings.")
                    .value_parser(clap::value_parser!(PathBuf))
            )
            .arg(
                Arg::new("output")
                    .short('o')
                    .long("output")
                    .value_name("FILE")
                    .help("Output file for saving results")
                    .long_help("Save monitoring results to a file. Supports JSON and Markdown formats based on file extension.")
                    .value_parser(clap::value_parser!(PathBuf))
            )
            .arg(
                Arg::new("format")
                    .short('f')
                    .long("format")
                    .value_name("FORMAT")
                    .help("Output format")
                    .long_help("Format for saved output: json, markdown, or csv")
                    .value_parser(["json", "markdown", "csv"])
                    .default_value("json")
            )
            .arg(
                Arg::new("filter-severity")
                    .long("filter-severity")
                    .value_name("LEVEL")
                    .help("Only show events of specified severity or higher")
                    .value_parser(["low", "medium", "high", "critical"])
            )
            .arg(
                Arg::new("no-header")
                    .long("no-header")
                    .help("Suppress column headers in output")
                    .action(clap::ArgAction::SetTrue)
            )
            .arg(
                Arg::new("timestamp-format")
                    .long("timestamp-format")
                    .value_name("FORMAT")
                    .help("Timestamp format for events")
                    .value_parser(["unix", "iso8601", "relative"])
                    .default_value("iso8601")
            )
            .subcommand(
                Command::new("report")
                    .about("Generate reports from saved monitoring data")
                    .arg(
                        Arg::new("input")
                            .value_name("FILE")
                            .help("Input file containing monitoring data")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf))
                    )
                    .arg(
                        Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_name("FORMAT")
                            .help("Report format")
                            .value_parser(["summary", "detailed", "json", "markdown"])
                            .default_value("summary")
                    )
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .value_name("FILE")
                            .help("Output file for the report")
                            .value_parser(clap::value_parser!(PathBuf))
                    )
            )
            .subcommand(
                Command::new("config")
                    .about("Configuration management")
                    .subcommand(
                        Command::new("generate")
                            .about("Generate a sample configuration file")
                            .arg(
                                Arg::new("output")
                                    .short('o')
                                    .long("output")
                                    .value_name("FILE")
                                    .help("Output configuration file path")
                                    .default_value("bee-trace.yaml")
                                    .value_parser(clap::value_parser!(PathBuf))
                            )
                    )
                    .subcommand(
                        Command::new("validate")
                            .about("Validate a configuration file")
                            .arg(
                                Arg::new("config")
                                    .value_name("FILE")
                                    .help("Configuration file to validate")
                                    .required(true)
                                    .value_parser(clap::value_parser!(PathBuf))
                            )
                    )
            );

        Self { app }
    }

    pub fn get_matches(self) -> ArgMatches {
        self.app.get_matches()
    }

    pub fn try_get_matches(self) -> Result<ArgMatches, clap::Error> {
        self.app.try_get_matches()
    }
}

impl Default for CliApp {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CliConfig {
    pub probe_type: String,
    pub duration: Option<Duration>,
    pub command_filter: Option<String>,
    pub verbose: bool,
    pub security_mode: bool,
    pub config_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub output_format: String,
    pub filter_severity: Option<String>,
    pub no_header: bool,
    pub timestamp_format: String,
}

impl CliConfig {
    pub fn from_matches(matches: &ArgMatches) -> anyhow::Result<Self> {
        let probe_type = matches.get_one::<String>("probe-type").unwrap().clone();

        let duration = matches
            .get_one::<u64>("duration")
            .map(|&d| Duration::from_secs(d));

        let command_filter = matches.get_one::<String>("command").cloned();

        let verbose = matches.get_flag("verbose");
        let security_mode = matches.get_flag("security-mode");
        let no_header = matches.get_flag("no-header");

        let config_file = matches.get_one::<PathBuf>("config").cloned();

        let output_file = matches.get_one::<PathBuf>("output").cloned();

        let output_format = matches.get_one::<String>("format").unwrap().clone();

        let filter_severity = matches.get_one::<String>("filter-severity").cloned();

        let timestamp_format = matches
            .get_one::<String>("timestamp-format")
            .unwrap()
            .clone();

        Ok(Self {
            probe_type,
            duration,
            command_filter,
            verbose,
            security_mode,
            config_file,
            output_file,
            output_format,
            filter_severity,
            no_header,
            timestamp_format,
        })
    }

    pub fn merge_with_configuration(&mut self, config: &Configuration) -> anyhow::Result<()> {
        // Merge monitoring settings
        if self.duration.is_none() {
            self.duration = config.monitoring.duration;
        }

        if !self.verbose {
            self.verbose = config.output.verbose;
        }

        if !self.security_mode {
            self.security_mode = config.monitoring.security_mode;
        }

        // Merge output settings - removed unused fields (no_header, output_file, format, timestamp_format)
        // and may need conversion from the enum types in Configuration

        Ok(())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let valid_probe_types = ["file_monitor", "network_monitor", "memory_monitor", "all"];

        if !valid_probe_types.contains(&self.probe_type.as_str()) {
            return Err(anyhow::anyhow!("Invalid probe type: {}", self.probe_type));
        }

        if let Some(severity) = &self.filter_severity {
            let valid_severities = ["low", "medium", "high", "critical"];
            if !valid_severities.contains(&severity.as_str()) {
                return Err(anyhow::anyhow!("Invalid severity filter: {}", severity));
            }
        }

        let valid_formats = ["json", "markdown", "csv"];
        if !valid_formats.contains(&self.output_format.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid output format: {}. Valid formats: {:?}",
                self.output_format,
                valid_formats
            ));
        }

        let valid_timestamp_formats = ["unix", "iso8601", "relative"];
        if !valid_timestamp_formats.contains(&self.timestamp_format.as_str()) {
            return Err(anyhow::anyhow!(
                "Invalid timestamp format: {}. Valid formats: {:?}",
                self.timestamp_format,
                valid_timestamp_formats
            ));
        }

        Ok(())
    }

    pub fn should_show_severity(&self, severity: &str) -> bool {
        if let Some(min_severity) = &self.filter_severity {
            let severity_levels = ["low", "medium", "high", "critical"];
            let min_index = severity_levels
                .iter()
                .position(|&s| s == min_severity)
                .unwrap_or(0);
            let event_index = severity_levels
                .iter()
                .position(|&s| s == severity)
                .unwrap_or(0);
            return event_index >= min_index;
        }
        true
    }
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

    #[test]
    fn should_create_cli_app() {
        let app = CliApp::new();
        assert_eq!(app.app.get_name(), "bee-trace");
    }

    #[test]
    fn should_parse_basic_args() {
        let app = CliApp::new();
        let matches = app
            .app
            .try_get_matches_from(vec!["bee-trace", "--probe-type", "file_monitor"])
            .unwrap();

        let config = CliConfig::from_matches(&matches).unwrap();
        assert_eq!(config.probe_type, "file_monitor");
        assert!(!config.verbose);
        assert!(!config.security_mode);
    }

    #[test]
    fn should_parse_complex_args() {
        let app = CliApp::new();
        let matches = app
            .app
            .try_get_matches_from(vec![
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

        let config = CliConfig::from_matches(&matches).unwrap();
        assert_eq!(config.probe_type, "network_monitor");
        assert_eq!(config.duration, Some(Duration::from_secs(30)));
        assert_eq!(config.command_filter, Some("nginx".to_string()));
        assert!(config.verbose);
        assert!(config.security_mode);
    }

    #[test]
    fn should_validate_probe_types() {
        let config = CliConfig {
            probe_type: "invalid_probe".to_string(),
            duration: None,
            command_filter: None,
            verbose: false,
            security_mode: false,
            config_file: None,
            output_file: None,
            output_format: "json".to_string(),
            filter_severity: None,
            no_header: false,
            timestamp_format: "iso8601".to_string(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn should_validate_severity_filters() {
        let config = CliConfig {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command_filter: None,
            verbose: false,
            security_mode: false,
            config_file: None,
            output_file: None,
            output_format: "json".to_string(),
            filter_severity: Some("invalid".to_string()),
            no_header: false,
            timestamp_format: "iso8601".to_string(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn should_filter_severity_correctly() {
        let config = CliConfig {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command_filter: None,
            verbose: false,
            security_mode: false,
            config_file: None,
            output_file: None,
            output_format: "json".to_string(),
            filter_severity: Some("medium".to_string()),
            no_header: false,
            timestamp_format: "iso8601".to_string(),
        };

        assert!(!config.should_show_severity("low"));
        assert!(config.should_show_severity("medium"));
        assert!(config.should_show_severity("high"));
        assert!(config.should_show_severity("critical"));
    }
}
