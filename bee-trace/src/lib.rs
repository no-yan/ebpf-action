use bee_trace_common::FileReadEvent;
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[clap(name = "bee-trace", about = "eBPF file reading monitor")]
pub struct Args {
    #[clap(short, long, default_value = "vfs_read")]
    pub probe_type: String,

    #[clap(short, long, help = "Duration to run the tracer in seconds")]
    pub duration: Option<u64>,

    #[clap(short, long, help = "Filter by process name")]
    pub command: Option<String>,

    #[clap(short, long, help = "Show verbose output")]
    pub verbose: bool,
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        match self.probe_type.as_str() {
            "vfs_read" | "sys_enter_read" => Ok(()),
            _ => Err(format!("Unsupported probe type: {}", self.probe_type)),
        }
    }

    pub fn should_filter_event(&self, event: &FileReadEvent) -> bool {
        if let Some(cmd_filter) = &self.command {
            let comm = event.command_as_str();
            return comm.contains(cmd_filter);
        }
        true
    }

    pub fn should_show_event(&self, event: &FileReadEvent) -> bool {
        if !self.verbose && (event.filename_as_str().is_empty()) {
            return false;
        }
        true
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
                "{:<8} {:<8} {:<16} {:<64}",
                "PID", "UID", "COMMAND", "FILENAME"
            )
        } else {
            format!(
                "{:<8} {:<16} {:<48}",
                "PID", "COMMAND", "FILENAME"
            )
        }
    }

    pub fn separator(&self) -> String {
        if self.verbose {
            "-".repeat(106)
        } else {
            "-".repeat(74)
        }
    }

    pub fn format_event(&self, event: &FileReadEvent) -> String {
        let comm = event.command_as_str();
        let filename = event.filename_as_str();

        if self.verbose {
            format!(
                "{:<8} {:<8} {:<16} {:<64}",
                event.pid, event.uid, comm, filename
            )
        } else {
            let truncated_filename = if filename.len() > 48 {
                format!("{}...", &filename[..45])
            } else {
                filename.to_string()
            };
            format!("{:<8} {:<16} {:<48}", event.pid, comm, truncated_filename)
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
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };
            assert!(vfs_args.validate().is_ok());

            let syscall_args = Args {
                probe_type: "sys_enter_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };
            assert!(syscall_args.validate().is_ok());
        }

        #[test]
        fn should_reject_invalid_probe_types() {
            let invalid_args = Args {
                probe_type: "invalid_probe".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };

            let result = invalid_args.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unsupported probe type"));
        }
    }

    mod event_filtering {
        use super::*;

        #[test]
        fn should_show_all_events_when_no_command_filter() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };

            let event = FileReadEvent::new()
                .with_command(b"cat")
                .with_filename(b"/etc/passwd");

            assert!(args.should_filter_event(&event));
        }

        #[test]
        fn should_filter_events_by_command() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
            };

            let matching_event = FileReadEvent::new()
                .with_command(b"cat")
                .with_filename(b"/etc/passwd");
            assert!(args.should_filter_event(&matching_event));

            let non_matching_event = FileReadEvent::new()
                .with_command(b"vim")
                .with_filename(b"/etc/passwd");
            assert!(!args.should_filter_event(&non_matching_event));
        }

        #[test]
        fn should_filter_by_partial_command_match() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
            };

            let event = FileReadEvent::new()
                .with_command(b"concatenate")
                .with_filename(b"/etc/passwd");

            assert!(args.should_filter_event(&event));
        }
    }

    mod event_visibility {
        use super::*;

        #[test]
        fn should_show_all_events_in_verbose_mode() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: true,
            };

            let empty_event = FileReadEvent::new();
            assert!(args.should_show_event(&empty_event));

            let zero_bytes_event = FileReadEvent::new().with_filename(b"/etc/passwd");
            assert!(args.should_show_event(&zero_bytes_event));
        }

        #[test]
        fn should_hide_empty_events_in_non_verbose_mode() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };

            let empty_filename_event = FileReadEvent::new();
            assert!(!args.should_show_event(&empty_filename_event));

            let valid_event = FileReadEvent::new().with_filename(b"/etc/passwd");
            assert!(args.should_show_event(&valid_event));
        }

        #[test]
        fn should_show_valid_events_in_non_verbose_mode() {
            let args = Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            };

            let valid_event = FileReadEvent::new().with_filename(b"/etc/passwd");
            assert!(args.should_show_event(&valid_event));
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
            assert!(header.contains("FILENAME"));
        }

        #[test]
        fn should_format_header_for_non_verbose_mode() {
            let formatter = EventFormatter::new(false);
            let header = formatter.header();

            assert!(header.contains("PID"));
            assert!(!header.contains("UID"));
            assert!(header.contains("COMMAND"));
            assert!(header.contains("FILENAME"));
        }

        #[test]
        fn should_provide_correct_separator_length() {
            let verbose_formatter = EventFormatter::new(true);
            assert_eq!(verbose_formatter.separator().len(), 106);

            let non_verbose_formatter = EventFormatter::new(false);
            assert_eq!(non_verbose_formatter.separator().len(), 74);
        }

        #[test]
        fn should_format_event_in_verbose_mode() {
            let formatter = EventFormatter::new(true);
            let event = FileReadEvent::new()
                .with_pid(1234)
                .with_uid(1000)
                .with_command(b"cat")
                .with_filename(b"/etc/passwd");

            let formatted = formatter.format_event(&event);

            assert!(formatted.contains("1234"));
            assert!(formatted.contains("1000"));
            assert!(formatted.contains("cat"));
            assert!(formatted.contains("/etc/passwd"));
        }

        #[test]
        fn should_format_event_in_non_verbose_mode() {
            let formatter = EventFormatter::new(false);
            let event = FileReadEvent::new()
                .with_pid(1234)
                .with_uid(1000)
                .with_command(b"cat")
                .with_filename(b"/etc/passwd");

            let formatted = formatter.format_event(&event);

            assert!(formatted.contains("1234"));
            assert!(!formatted.contains("1000")); // UID not shown in non-verbose
            assert!(formatted.contains("cat"));
            assert!(formatted.contains("/etc/passwd"));
        }

        #[test]
        fn should_truncate_long_filename_in_non_verbose_mode() {
            let formatter = EventFormatter::new(false);
            let long_filename = "a".repeat(60);
            let event = FileReadEvent::new()
                .with_pid(1234)
                .with_command(b"cat")
                .with_filename(long_filename.as_bytes());

            let formatted = formatter.format_event(&event);

            assert!(formatted.contains("..."));
            assert!(formatted.len() <= 74); // Should not exceed expected width
        }

        #[test]
        fn should_not_truncate_short_filename() {
            let formatter = EventFormatter::new(false);
            let short_filename = "/etc/passwd";
            let event = FileReadEvent::new()
                .with_pid(1234)
                .with_command(b"cat")
                .with_filename(short_filename.as_bytes());

            let formatted = formatter.format_event(&event);

            assert!(!formatted.contains("..."));
            assert!(formatted.contains("/etc/passwd"));
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
