//! Test utilities and helpers following t-wada's testing principles
//!
//! This module provides reusable test utilities that make tests more readable,
//! maintainable, and focused on behavior rather than implementation details.

use bee_trace_common::{SecretAccessEvent, SecurityEventBuilder as CommonBuilder};

/// Builder for creating test SecurityEvent instances with fluent API
pub struct SecurityEventBuilder {
    event: SecretAccessEvent,
}

impl Default for SecurityEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityEventBuilder {
    pub fn new() -> Self {
        Self {
            event: SecretAccessEvent::new(),
        }
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.event = CommonBuilder::with_pid(self.event, pid);
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.event = CommonBuilder::with_uid(self.event, uid);
        self
    }

    pub fn command(mut self, cmd: &str) -> Self {
        self.event = CommonBuilder::with_command(self.event, cmd.as_bytes());
        self
    }

    pub fn file_access(mut self, path: &str) -> Self {
        self.event = self.event.with_file_access(path.as_bytes());
        self
    }

    pub fn env_var_access(mut self, var: &str) -> Self {
        self.event = self.event.with_env_var_access(var.as_bytes());
        self
    }

    pub fn build(self) -> SecretAccessEvent {
        self.event
    }
}

/// Common test event factories with descriptive names
pub mod events {
    use super::*;

    pub fn typical_cat_reading_passwd() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(1234)
            .uid(1000)
            .command("cat")
            .file_access("/etc/passwd")
            .build()
    }

    pub fn system_process_reading_proc() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(1)
            .uid(0)
            .command("init")
            .file_access("/proc/version")
            .build()
    }

    pub fn editor_opening_config() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(5678)
            .uid(1001)
            .command("vim")
            .file_access("/home/user/.vimrc")
            .build()
    }

    pub fn empty_access_attempt() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(9999)
            .uid(1000)
            .command("test")
            .build()
    }

    pub fn env_var_access() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(1111)
            .uid(1000)
            .command("env")
            .env_var_access("SECRET_API_KEY")
            .build()
    }

    pub fn large_file_operation() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(2222)
            .uid(1000)
            .command("bigfilehandler")
            .file_access("/var/log/huge.log")
            .build()
    }

    pub fn with_unicode_path() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(3333)
            .uid(1000)
            .command("cat")
            .file_access("🦀/rust/file.rs")
            .build()
    }

    pub fn with_very_long_path() -> SecretAccessEvent {
        let long_path = format!(
            "/very/long/path/to/some/deeply/nested/directory/structure/with/a/very/long/filename/{}",
            "x".repeat(100)
        );
        SecurityEventBuilder::new()
            .pid(4444)
            .uid(1000)
            .command("longpathtool")
            .file_access(&long_path)
            .build()
    }

    pub fn with_max_values() -> SecretAccessEvent {
        SecurityEventBuilder::new()
            .pid(u32::MAX)
            .uid(u32::MAX)
            .command("maxcmd")
            .file_access("/max/path")
            .build()
    }

    pub fn with_zero_values() -> SecretAccessEvent {
        SecurityEventBuilder::new().build() // All defaults are zero
    }
}

/// Test scenarios for different filtering conditions
pub mod scenarios {
    use bee_trace::{Args, SecurityEvent};

    use super::*;

    pub struct TestScenario {
        pub name: &'static str,
        pub args: Args,
        pub events: Vec<SecurityEvent>,
        pub expected_output_count: usize,
        pub description: &'static str,
    }

    pub fn no_filtering() -> TestScenario {
        TestScenario {
            name: "no_filtering",
            args: Args {
                probe_type: "file_monitor".to_string(),
                duration: None,
                command: None,
                verbose: false,
                security_mode: false,
                config: None,
            },
            events: vec![
                SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()),
                SecurityEvent::SecretAccess(events::editor_opening_config()),
                SecurityEvent::SecretAccess(events::system_process_reading_proc()),
            ],
            expected_output_count: 3,
            description: "All valid events should be shown when no filters are applied",
        }
    }

    pub fn command_filtering() -> TestScenario {
        TestScenario {
            name: "command_filtering",
            args: Args {
                probe_type: "file_monitor".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
                security_mode: false,
                config: None,
            },
            events: vec![
                SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()),
                SecurityEvent::SecretAccess(events::editor_opening_config()),
                SecurityEvent::SecretAccess(events::with_unicode_path()), // Also has "cat" command
            ],
            expected_output_count: 2,
            description: "Only events matching the command filter should be shown",
        }
    }

    pub fn security_mode_showing_all_events() -> TestScenario {
        TestScenario {
            name: "security_mode_showing_all_events",
            args: Args {
                probe_type: "file_monitor".to_string(),
                duration: None,
                command: None,
                verbose: true,
                security_mode: true,
                config: None,
            },
            events: vec![
                SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()),
                SecurityEvent::SecretAccess(events::empty_access_attempt()),
                SecurityEvent::SecretAccess(events::env_var_access()),
                SecurityEvent::SecretAccess(events::with_zero_values()),
            ],
            expected_output_count: 4,
            description: "Security mode should show all events",
        }
    }

    pub fn mixed_filtering() -> TestScenario {
        TestScenario {
            name: "mixed_filtering",
            args: Args {
                probe_type: "file_monitor".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
                security_mode: false,
                config: None,
            },
            events: vec![
                SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()), // Should pass
                SecurityEvent::SecretAccess(events::editor_opening_config()), // Should fail: wrong command
                SecurityEvent::SecretAccess(
                    SecurityEventBuilder::new() // Should fail: matches command but empty
                        .command("cat")
                        .build(),
                ),
                SecurityEvent::SecretAccess(
                    SecurityEventBuilder::new() // Should pass: partial match + valid
                        .command("concatenate")
                        .file_access("/tmp/test")
                        .build(),
                ),
            ],
            expected_output_count: 2,
            description: "Should apply both command filtering and visibility rules",
        }
    }

    pub fn all_scenarios() -> Vec<TestScenario> {
        vec![
            no_filtering(),
            command_filtering(),
            security_mode_showing_all_events(),
            mixed_filtering(),
        ]
    }
}

/// Utilities for testing formatting and output
pub mod formatting {
    use bee_trace::SecurityEvent;

    use super::*;

    pub struct FormattingTestCase {
        pub name: &'static str,
        pub event: SecurityEvent,
        pub verbose: bool,
        pub expected_contains: Vec<&'static str>,
        pub expected_not_contains: Vec<&'static str>,
        pub max_length: Option<usize>,
    }

    pub fn standard_formatting_cases() -> Vec<FormattingTestCase> {
        vec![
            FormattingTestCase {
                name: "verbose_output_includes_uid",
                event: SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()),
                verbose: true,
                expected_contains: vec!["1234", "1000", "cat", "/etc/passwd"],
                expected_not_contains: vec!["..."],
                max_length: None,
            },
            FormattingTestCase {
                name: "non_verbose_excludes_uid",
                event: SecurityEvent::SecretAccess(events::typical_cat_reading_passwd()),
                verbose: false,
                expected_contains: vec!["1234", "cat", "/etc/passwd"],
                expected_not_contains: vec!["1000"], // UID not shown in non-verbose
                max_length: Some(90),
            },
            FormattingTestCase {
                name: "long_path_truncation_in_normal_mode",
                event: SecurityEvent::SecretAccess(events::with_very_long_path()),
                verbose: false,
                expected_contains: vec!["4444", "longpathtool", "..."],
                expected_not_contains: vec![],
                max_length: Some(90),
            },
            FormattingTestCase {
                name: "long_path_no_truncation_in_verbose_mode",
                event: SecurityEvent::SecretAccess(events::with_very_long_path()),
                verbose: true,
                expected_contains: vec!["4444", "1000", "longpathtool", "/very/long/path"],
                expected_not_contains: vec!["..."],
                max_length: None,
            },
            FormattingTestCase {
                name: "unicode_path_handling",
                event: SecurityEvent::SecretAccess(events::with_unicode_path()),
                verbose: false,
                expected_contains: vec!["3333", "cat", "🦀"],
                expected_not_contains: vec![],
                max_length: Some(90),
            },
        ]
    }

    pub fn verify_formatting_case(test_case: &FormattingTestCase) -> Result<(), String> {
        use bee_trace::{EventFormatter, TableFormatter};
        let formatter = TableFormatter::new(test_case.verbose);
        let output = formatter.format_event(&test_case.event);

        // Check required contents
        for expected in &test_case.expected_contains {
            if !output.contains(expected) {
                return Err(format!(
                    "Test '{}': Expected '{}' in output: '{}'",
                    test_case.name, expected, output
                ));
            }
        }

        // Check forbidden contents
        for unexpected in &test_case.expected_not_contains {
            if output.contains(unexpected) {
                return Err(format!(
                    "Test '{}': Unexpected '{}' in output: '{}'",
                    test_case.name, unexpected, output
                ));
            }
        }

        // Check length constraints
        if let Some(max_len) = test_case.max_length {
            if output.len() > max_len {
                return Err(format!(
                    "Test '{}': Output too long ({} > {}): '{}'",
                    test_case.name,
                    output.len(),
                    max_len,
                    output
                ));
            }
        }

        Ok(())
    }
}

/// Performance testing utilities
pub mod performance {
    use std::time::{Duration, Instant};

    use super::*;

    pub struct PerformanceTest {
        pub name: &'static str,
        pub operation: Box<dyn Fn()>,
        pub iterations: usize,
        pub max_duration: Duration,
    }

    impl PerformanceTest {
        pub fn run(&self) -> Result<Duration, String> {
            let start = Instant::now();

            for _ in 0..self.iterations {
                (self.operation)();
            }

            let elapsed = start.elapsed();

            if elapsed > self.max_duration {
                return Err(format!(
                    "Performance test '{}' too slow: {:?} > {:?}",
                    self.name, elapsed, self.max_duration
                ));
            }

            Ok(elapsed)
        }
    }

    pub fn event_creation_performance() -> PerformanceTest {
        PerformanceTest {
            name: "event_creation",
            operation: Box::new(|| {
                let _event = events::typical_cat_reading_passwd();
            }),
            iterations: 10_000,
            max_duration: Duration::from_millis(50),
        }
    }

    pub fn event_formatting_performance() -> PerformanceTest {
        PerformanceTest {
            name: "event_formatting",
            operation: Box::new(|| {
                let event =
                    bee_trace::SecurityEvent::SecretAccess(events::typical_cat_reading_passwd());
                let formatter = bee_trace::TableFormatter::new(false);
                use bee_trace::EventFormatter;
                let _output = formatter.format_event(&event);
            }),
            iterations: 10_000,
            max_duration: Duration::from_millis(50),
        }
    }

    pub fn string_conversion_performance() -> PerformanceTest {
        PerformanceTest {
            name: "string_conversion",
            operation: Box::new(|| {
                use bee_trace_common::SecurityEventData;
                let event = events::with_very_long_path();
                let _path = event.path_or_var_as_str();
                let _command = event.command_as_str();
            }),
            iterations: 10_000,
            max_duration: Duration::from_millis(50),
        }
    }
}

/// Test data generators for property-based testing style
pub mod generators {
    use std::collections::VecDeque;

    use super::*;

    pub struct EventGenerator {
        pid_counter: u32,
        commands: VecDeque<&'static str>,
        paths: VecDeque<&'static str>,
        env_vars: VecDeque<&'static str>,
    }

    impl Default for EventGenerator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl EventGenerator {
        pub fn new() -> Self {
            Self {
                pid_counter: 1000,
                commands: vec![
                    "cat", "vim", "ls", "grep", "find", "head", "tail", "less", "more", "cp",
                ]
                .into(),
                paths: vec![
                    "/etc/passwd",
                    "/etc/shadow",
                    "/var/log/syslog",
                    "/tmp/test",
                    "/home/user/.bashrc",
                    "/usr/bin/ls",
                    "/lib/libc.so",
                    "/proc/version",
                    "/dev/null",
                    "/sys/kernel/debug",
                ]
                .into(),
                env_vars: vec![
                    "SECRET_API_KEY",
                    "DATABASE_PASSWORD",
                    "JWT_SECRET",
                    "AWS_SECRET_ACCESS_KEY",
                    "GITHUB_TOKEN",
                ]
                .into(),
            }
        }

        pub fn next_event(&mut self) -> SecretAccessEvent {
            self.pid_counter += 1;

            let command = self.commands.pop_front().unwrap_or("unknown");
            self.commands.push_back(command);

            let path = self.paths.pop_front().unwrap_or("/unknown");
            self.paths.push_back(path);

            SecurityEventBuilder::new()
                .pid(self.pid_counter)
                .uid(1000)
                .command(command)
                .file_access(path)
                .build()
        }

        pub fn next_env_event(&mut self) -> SecretAccessEvent {
            self.pid_counter += 1;

            let command = self.commands.pop_front().unwrap_or("unknown");
            self.commands.push_back(command);

            let env_var = self.env_vars.pop_front().unwrap_or("UNKNOWN_VAR");
            self.env_vars.push_back(env_var);

            SecurityEventBuilder::new()
                .pid(self.pid_counter)
                .uid(1000)
                .command(command)
                .env_var_access(env_var)
                .build()
        }

        pub fn generate_batch(&mut self, count: usize) -> Vec<SecretAccessEvent> {
            (0..count).map(|_| self.next_event()).collect()
        }

        pub fn generate_mixed_batch(&mut self, count: usize) -> Vec<SecretAccessEvent> {
            (0..count)
                .map(|i| {
                    if i % 2 == 0 {
                        self.next_event()
                    } else {
                        self.next_env_event()
                    }
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn event_builder_should_create_valid_events() {
        use bee_trace_common::SecurityEventData;
        let event = SecurityEventBuilder::new()
            .pid(1234)
            .command("test")
            .file_access("/tmp/test")
            .build();

        assert_eq!(event.pid, 1234);
        assert_eq!(event.command_as_str(), "test");
        assert_eq!(event.path_or_var_as_str(), "/tmp/test");
    }

    #[test]
    fn event_generator_should_produce_unique_events() {
        let mut generator = generators::EventGenerator::new();
        let events = generator.generate_batch(5);

        assert_eq!(events.len(), 5);

        // All events should have different PIDs
        let pids: std::collections::HashSet<_> = events.iter().map(|e| e.pid).collect();
        assert_eq!(pids.len(), 5);
    }

    #[test]
    fn formatting_test_cases_should_be_valid() {
        let test_cases = formatting::standard_formatting_cases();
        for test_case in &test_cases {
            assert!(
                formatting::verify_formatting_case(test_case).is_ok(),
                "Formatting test case '{}' failed",
                test_case.name
            );
        }
    }

    #[test]
    fn performance_tests_should_pass() {
        let tests = vec![
            performance::event_creation_performance(),
            performance::event_formatting_performance(),
            performance::string_conversion_performance(),
        ];

        for test in tests {
            assert!(
                test.run().is_ok(),
                "Performance test '{}' failed",
                test.name
            );
        }
    }
}
