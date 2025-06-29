use bee_trace::{Args, SecurityEvent};
use bee_trace_common::SecretAccessEvent;
use clap::Parser;

mod cli_argument_parsing {
    use super::*;

    #[test]
    fn should_parse_default_arguments() {
        let args = Args::try_parse_from(["bee-trace"]).unwrap();

        assert_eq!(args.probe_type, "file_monitor");
        assert_eq!(args.duration, None);
        assert_eq!(args.command, None);
        assert!(!args.verbose);
        assert!(!args.security_mode);
        assert_eq!(args.config, None);
    }

    #[test]
    fn should_parse_probe_type_argument() {
        let args = Args::try_parse_from(["bee-trace", "--probe-type", "network_monitor"]).unwrap();

        assert_eq!(args.probe_type, "network_monitor");
    }

    #[test]
    fn should_parse_short_probe_type_argument() {
        let args = Args::try_parse_from(["bee-trace", "-p", "memory_monitor"]).unwrap();

        assert_eq!(args.probe_type, "memory_monitor");
    }

    #[test]
    fn should_parse_duration_argument() {
        let args = Args::try_parse_from(["bee-trace", "--duration", "30"]).unwrap();

        assert_eq!(args.duration, Some(30));
    }

    #[test]
    fn should_parse_short_duration_argument() {
        let args = Args::try_parse_from(["bee-trace", "-d", "60"]).unwrap();

        assert_eq!(args.duration, Some(60));
    }

    #[test]
    fn should_parse_command_filter_argument() {
        let args = Args::try_parse_from(["bee-trace", "--command", "cat"]).unwrap();

        assert_eq!(args.command, Some("cat".to_string()));
    }

    #[test]
    fn should_parse_short_command_filter_argument() {
        let args = Args::try_parse_from(["bee-trace", "-c", "vim"]).unwrap();

        assert_eq!(args.command, Some("vim".to_string()));
    }

    #[test]
    fn should_parse_verbose_flag() {
        let args = Args::try_parse_from(["bee-trace", "--verbose"]).unwrap();

        assert!(args.verbose);
    }

    #[test]
    fn should_parse_short_verbose_flag() {
        let args = Args::try_parse_from(["bee-trace", "-v"]).unwrap();

        assert!(args.verbose);
    }

    #[test]
    fn should_parse_all_arguments_together() {
        let args = Args::try_parse_from([
            "bee-trace",
            "--probe-type",
            "all",
            "--duration",
            "120",
            "--command",
            "python",
            "--verbose",
        ])
        .unwrap();

        assert_eq!(args.probe_type, "all");
        assert_eq!(args.duration, Some(120));
        assert_eq!(args.command, Some("python".to_string()));
        assert!(args.verbose);
    }

    #[test]
    fn should_fail_on_invalid_duration() {
        let result = Args::try_parse_from(["bee-trace", "--duration", "not-a-number"]);

        assert!(result.is_err());
    }

    #[test]
    fn should_fail_on_unknown_argument() {
        let result = Args::try_parse_from(["bee-trace", "--unknown-flag"]);

        assert!(result.is_err());
    }

    #[test]
    fn should_show_help_text() {
        let result = Args::try_parse_from(["bee-trace", "--help"]);

        // Should fail with help text (clap exits with error code 0 for help)
        assert!(result.is_err());
    }
}

mod probe_type_validation {
    use super::*;

    #[test]
    fn should_validate_probe_types() {
        let valid_file = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        assert!(valid_file.validate().is_ok());

        let valid_network = Args {
            probe_type: "network_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        assert!(valid_network.validate().is_ok());

        let valid_all = Args {
            probe_type: "all".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        assert!(valid_all.validate().is_ok());

        let invalid = Args {
            probe_type: "invalid_probe".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        assert!(invalid.validate().is_err());
    }
}

mod security_event_integration {
    use super::*;
    use bee_trace_common::SecurityEventBuilder;

    fn create_test_event() -> SecurityEvent {
        let secret_event = SecurityEventBuilder::with_command(
            SecurityEventBuilder::with_uid(
                SecurityEventBuilder::with_pid(SecretAccessEvent::new(), 1234),
                1000,
            ),
            b"cat",
        )
        .with_file_access(b"/etc/passwd");
        SecurityEvent::SecretAccess(secret_event)
    }

    #[test]
    fn should_process_valid_security_event() {
        let args = Args::try_parse_from(["bee-trace"]).unwrap();
        let formatter = bee_trace::TableFormatter::new(args.verbose);
        let event = create_test_event();

        assert!(args.should_filter_security_event(&event));
        assert!(args.should_show_security_event(&event));

        use bee_trace::EventFormatter;
        let formatted = formatter.format_event(&event);
        assert!(formatted.contains("1234"));
        assert!(formatted.contains("cat"));
    }

    #[test]
    fn should_filter_security_event_by_command() {
        let args = Args::try_parse_from(["bee-trace", "--command", "vim"]).unwrap();
        let event = create_test_event(); // has "cat" command

        assert!(!args.should_filter_security_event(&event));
    }

    #[test]
    fn should_allow_matching_command() {
        let args = Args::try_parse_from(["bee-trace", "--command", "cat"]).unwrap();
        let event = create_test_event();

        assert!(args.should_filter_security_event(&event));
    }
}
