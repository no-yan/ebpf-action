use bee_trace::{Args, EventFormatter};
use bee_trace_common::FileReadEvent;
use clap::Parser;

mod cli_argument_parsing {
    use super::*;

    #[test]
    fn should_parse_default_arguments() {
        let args = Args::try_parse_from(&["bee-trace"]).unwrap();

        assert_eq!(args.probe_type, "vfs_read");
        assert_eq!(args.duration, None);
        assert_eq!(args.command, None);
        assert!(!args.verbose);
    }

    #[test]
    fn should_parse_probe_type_argument() {
        let args = Args::try_parse_from(&["bee-trace", "--probe-type", "sys_enter_read"]).unwrap();

        assert_eq!(args.probe_type, "sys_enter_read");
    }

    #[test]
    fn should_parse_short_probe_type_argument() {
        let args = Args::try_parse_from(&["bee-trace", "-p", "sys_enter_read"]).unwrap();

        assert_eq!(args.probe_type, "sys_enter_read");
    }

    #[test]
    fn should_parse_duration_argument() {
        let args = Args::try_parse_from(&["bee-trace", "--duration", "30"]).unwrap();

        assert_eq!(args.duration, Some(30));
    }

    #[test]
    fn should_parse_short_duration_argument() {
        let args = Args::try_parse_from(&["bee-trace", "-d", "60"]).unwrap();

        assert_eq!(args.duration, Some(60));
    }

    #[test]
    fn should_parse_command_filter_argument() {
        let args = Args::try_parse_from(&["bee-trace", "--command", "cat"]).unwrap();

        assert_eq!(args.command, Some("cat".to_string()));
    }

    #[test]
    fn should_parse_short_command_filter_argument() {
        let args = Args::try_parse_from(&["bee-trace", "-c", "vim"]).unwrap();

        assert_eq!(args.command, Some("vim".to_string()));
    }

    #[test]
    fn should_parse_verbose_flag() {
        let args = Args::try_parse_from(&["bee-trace", "--verbose"]).unwrap();

        assert!(args.verbose);
    }

    #[test]
    fn should_parse_short_verbose_flag() {
        let args = Args::try_parse_from(&["bee-trace", "-v"]).unwrap();

        assert!(args.verbose);
    }

    #[test]
    fn should_parse_all_arguments_together() {
        let args = Args::try_parse_from(&[
            "bee-trace",
            "--probe-type",
            "sys_enter_read",
            "--duration",
            "120",
            "--command",
            "python",
            "--verbose",
        ])
        .unwrap();

        assert_eq!(args.probe_type, "sys_enter_read");
        assert_eq!(args.duration, Some(120));
        assert_eq!(args.command, Some("python".to_string()));
        assert!(args.verbose);
    }

    #[test]
    fn should_fail_on_invalid_duration() {
        let result = Args::try_parse_from(&["bee-trace", "--duration", "not-a-number"]);

        assert!(result.is_err());
    }

    #[test]
    fn should_fail_on_unknown_argument() {
        let result = Args::try_parse_from(&["bee-trace", "--unknown-flag"]);

        assert!(result.is_err());
    }

    #[test]
    fn should_show_help_text() {
        let result = Args::try_parse_from(&["bee-trace", "--help"]);

        // Should fail with help text (clap exits with error code 0 for help)
        assert!(result.is_err());
    }
}

mod end_to_end_scenarios {
    use super::*;

    fn create_test_event() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(1234)
            .with_uid(1000)
            .with_command(b"cat")
            .with_filename(b"/etc/passwd")
    }

    #[test]
    fn should_process_valid_event_without_filters() {
        let args = Args::try_parse_from(&["bee-trace"]).unwrap();
        let formatter = EventFormatter::new(args.verbose);
        let event = create_test_event();

        assert!(args.should_filter_event(&event));
        assert!(args.should_show_event(&event));

        let formatted = formatter.format_event(&event);
        assert!(formatted.contains("1234"));
        assert!(formatted.contains("cat"));
    }

    #[test]
    fn should_filter_event_by_command() {
        let args = Args::try_parse_from(&["bee-trace", "--command", "vim"]).unwrap();
        let event = create_test_event(); // has "cat" command

        assert!(!args.should_filter_event(&event));
    }

    #[test]
    fn should_allow_matching_command() {
        let args = Args::try_parse_from(&["bee-trace", "--command", "cat"]).unwrap();
        let event = create_test_event();

        assert!(args.should_filter_event(&event));
    }

    #[test]
    fn should_hide_empty_events_in_normal_mode() {
        let args = Args::try_parse_from(&["bee-trace"]).unwrap();
        let empty_event = FileReadEvent::new();

        assert!(!args.should_show_event(&empty_event));
    }

    #[test]
    fn should_show_empty_events_in_verbose_mode() {
        let args = Args::try_parse_from(&["bee-trace", "--verbose"]).unwrap();
        let empty_event = FileReadEvent::new();

        assert!(args.should_show_event(&empty_event));
    }

    #[test]
    fn should_format_output_differently_based_on_verbosity() {
        let event = create_test_event();

        let verbose_formatter = EventFormatter::new(true);
        let normal_formatter = EventFormatter::new(false);

        let verbose_output = verbose_formatter.format_event(&event);
        let normal_output = normal_formatter.format_event(&event);

        // Verbose should include UID
        assert!(verbose_output.contains("1000"));
        assert!(!normal_output.contains("1000"));

        // Both should include PID and command
        assert!(verbose_output.contains("1234"));
        assert!(normal_output.contains("1234"));
        assert!(verbose_output.contains("cat"));
        assert!(normal_output.contains("cat"));
    }

    #[test]
    fn should_validate_probe_types() {
        let valid_vfs = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
        };
        assert!(valid_vfs.validate().is_ok());

        let valid_syscall = Args {
            probe_type: "sys_enter_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
        };
        assert!(valid_syscall.validate().is_ok());

        let invalid = Args {
            probe_type: "invalid_probe".to_string(),
            duration: None,
            command: None,
            verbose: false,
        };
        assert!(invalid.validate().is_err());
    }
}

mod complex_filtering_scenarios {
    use super::*;

    #[test]
    fn should_handle_partial_command_matches() {
        let args = Args::try_parse_from(&["bee-trace", "--command", "cat"]).unwrap();

        let exact_match = FileReadEvent::new().with_command(b"cat");
        let partial_match = FileReadEvent::new().with_command(b"concatenate");
        let no_match = FileReadEvent::new().with_command(b"vim");

        assert!(args.should_filter_event(&exact_match));
        assert!(args.should_filter_event(&partial_match));
        assert!(!args.should_filter_event(&no_match));
    }

    #[test]
    fn should_handle_events_with_empty_filename() {
        let normal_args = Args::try_parse_from(&["bee-trace"]).unwrap();
        let verbose_args = Args::try_parse_from(&["bee-trace", "--verbose"]).unwrap();

        let empty_filename_event = FileReadEvent::new();

        assert!(!normal_args.should_show_event(&empty_filename_event));
        assert!(verbose_args.should_show_event(&empty_filename_event));
    }

    #[test]
    fn should_combine_command_filter_and_visibility_rules() {
        let args = Args::try_parse_from(&["bee-trace", "--command", "cat"]).unwrap();

        // Event matches command but has empty filename (should be filtered out)
        let filtered_event = FileReadEvent::new().with_command(b"cat");

        assert!(args.should_filter_event(&filtered_event)); // Passes command filter
        assert!(!args.should_show_event(&filtered_event)); // Fails visibility check

        // Event matches command and has valid data
        let visible_event = FileReadEvent::new()
            .with_command(b"cat")
            .with_filename(b"/etc/passwd");

        assert!(args.should_filter_event(&visible_event));
        assert!(args.should_show_event(&visible_event));
    }
}

mod output_formatting_edge_cases {
    use super::*;

    #[test]
    fn should_truncate_very_long_filenames() {
        let formatter = EventFormatter::new(false);
        let long_filename = "a".repeat(100);

        let event = FileReadEvent::new()
            .with_pid(1234)
            .with_command(b"cat")
            .with_filename(long_filename.as_bytes());

        let formatted = formatter.format_event(&event);
        assert!(formatted.contains("..."));
        assert!(formatted.len() <= 74); // Should fit in expected column width
    }

    #[test]
    fn should_handle_filenames_at_truncation_boundary() {
        let formatter = EventFormatter::new(false);
        let boundary_filename = "a".repeat(48); // Exactly at boundary

        let event = FileReadEvent::new()
            .with_pid(1234)
            .with_command(b"cat")
            .with_filename(boundary_filename.as_bytes());

        let formatted = formatter.format_event(&event);
        assert!(!formatted.contains("...")); // Should not truncate
        assert!(formatted.contains(&boundary_filename));
    }

    #[test]
    fn should_not_truncate_in_verbose_mode() {
        let formatter = EventFormatter::new(true);
        let long_filename = "a".repeat(100);

        let event = FileReadEvent::new()
            .with_pid(1234)
            .with_command(b"cat")
            .with_filename(long_filename.as_bytes());

        let formatted = formatter.format_event(&event);
        assert!(!formatted.contains("...")); // Verbose mode shows full filename
                                             // Since filename is truncated to 64 bytes in the struct, check for that much
        let expected_filename = &long_filename[..64];
        assert!(formatted.contains(expected_filename));
    }

    #[test]
    fn should_handle_events_with_invalid_utf8_gracefully() {
        let formatter = EventFormatter::new(false);

        let mut event = FileReadEvent::new();
        event.pid = 1234;
        event.comm[0] = 0xFF; // Invalid UTF-8
        event.comm[1] = 0xFE;
        event.filename[0] = 0xFF; // Invalid UTF-8
        event.filename[1] = 0xFE;
        event.filename_len = 2;

        let formatted = formatter.format_event(&event);
        // Should not panic and should produce some output
        assert!(formatted.contains("1234"));
    }

    #[test]
    fn should_align_columns_correctly() {
        let formatter = EventFormatter::new(false);

        let short_event = FileReadEvent::new()
            .with_pid(1)
            .with_command(b"x")
            .with_filename(b"/a");

        let long_event = FileReadEvent::new()
            .with_pid(999999)
            .with_command(b"very_long_command")
            .with_filename(b"/very/long/path/to/file");

        let short_formatted = formatter.format_event(&short_event);
        let long_formatted = formatter.format_event(&long_event);

        // Both should have consistent field positioning
        let short_parts: Vec<&str> = short_formatted.split_whitespace().collect();
        let long_parts: Vec<&str> = long_formatted.split_whitespace().collect();

        assert_eq!(short_parts.len(), long_parts.len()); // Same number of fields
        assert!(short_parts[0].len() <= 8); // PID fits in column
    }
}
