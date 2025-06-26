//! Test utilities and helpers following t-wada's testing principles
//!
//! This module provides reusable test utilities that make tests more readable,
//! maintainable, and focused on behavior rather than implementation details.


use bee_trace_common::FileReadEvent;

/// Builder for creating test FileReadEvent instances with fluent API
pub struct FileReadEventBuilder {
    event: FileReadEvent,
}

impl FileReadEventBuilder {
    pub fn new() -> Self {
        Self {
            event: FileReadEvent::new(),
        }
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.event = self.event.with_pid(pid);
        self
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.event = self.event.with_uid(uid);
        self
    }

    pub fn command(mut self, cmd: &str) -> Self {
        self.event = self.event.with_command(cmd.as_bytes());
        self
    }

    pub fn filename(mut self, filename: &str) -> Self {
        self.event = self.event.with_filename(filename.as_bytes());
        self
    }


    pub fn build(self) -> FileReadEvent {
        self.event
    }
}

/// Common test event factories with descriptive names
pub mod events {
    use super::*;

    pub fn typical_cat_reading_passwd() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(1234)
            .uid(1000)
            .command("cat")
            .filename("/etc/passwd")
            .build()
    }

    pub fn system_process_reading_proc() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(1)
            .uid(0)
            .command("init")
            .filename("/proc/version")
            .build()
    }

    pub fn editor_opening_config() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(5678)
            .uid(1001)
            .command("vim")
            .filename("/home/user/.vimrc")
            .build()
    }

    pub fn empty_read_attempt() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(9999)
            .uid(1000)
            .command("test")
            .filename("/tmp/empty")
            .build()
    }

    pub fn missing_filename() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(1111)
            .uid(1000)
            .command("mystery")
            .build()
    }

    pub fn large_file_operation() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(2222)
            .uid(1000)
            .command("bigfilehandler")
            .filename("/var/log/huge.log")
            .build()
    }

    pub fn with_unicode_path() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(3333)
            .uid(1000)
            .command("cat")
            .filename("🦀/rust/file.rs")
            .build()
    }

    pub fn with_very_long_path() -> FileReadEvent {
        let long_path = format!(
            "/very/long/path/to/some/deeply/nested/directory/structure/with/a/very/long/filename/{}",
            "x".repeat(100)
        );
        FileReadEventBuilder::new()
            .pid(4444)
            .uid(1000)
            .command("longpathtool")
            .filename(&long_path)
            .build()
    }

    pub fn with_max_values() -> FileReadEvent {
        FileReadEventBuilder::new()
            .pid(u32::MAX)
            .uid(u32::MAX)
            .command("maxcmd")
            .filename("/max/path")
            .build()
    }

    pub fn with_zero_values() -> FileReadEvent {
        FileReadEventBuilder::new().build() // All defaults are zero
    }
}

/// Test scenarios for different filtering conditions
pub mod scenarios {
    use bee_trace::Args;

    use super::*;

    pub struct TestScenario {
        pub name: &'static str,
        pub args: Args,
        pub events: Vec<FileReadEvent>,
        pub expected_output_count: usize,
        pub description: &'static str,
    }

    pub fn no_filtering() -> TestScenario {
        TestScenario {
            name: "no_filtering",
            args: Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            },
            events: vec![
                events::typical_cat_reading_passwd(),
                events::editor_opening_config(),
                events::system_process_reading_proc(),
            ],
            expected_output_count: 3,
            description: "All valid events should be shown when no filters are applied",
        }
    }

    pub fn command_filtering() -> TestScenario {
        TestScenario {
            name: "command_filtering",
            args: Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
            },
            events: vec![
                events::typical_cat_reading_passwd(),
                events::editor_opening_config(),
                events::with_unicode_path(), // Also has "cat" command
            ],
            expected_output_count: 2,
            description: "Only events matching the command filter should be shown",
        }
    }

    pub fn verbose_mode_showing_empty_events() -> TestScenario {
        TestScenario {
            name: "verbose_mode_showing_empty_events",
            args: Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: true,
            },
            events: vec![
                events::typical_cat_reading_passwd(),
                events::empty_read_attempt(),
                events::missing_filename(),
                events::with_zero_values(),
            ],
            expected_output_count: 4,
            description: "Verbose mode should show all events, including empty ones",
        }
    }

    pub fn normal_mode_hiding_empty_events() -> TestScenario {
        TestScenario {
            name: "normal_mode_hiding_empty_events",
            args: Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: None,
                verbose: false,
            },
            events: vec![
                events::typical_cat_reading_passwd(),
                events::empty_read_attempt(),
                events::missing_filename(),
                events::with_zero_values(),
            ],
            expected_output_count: 1,
            description: "Normal mode should hide events with empty filenames or zero bytes",
        }
    }

    pub fn mixed_filtering() -> TestScenario {
        TestScenario {
            name: "mixed_filtering",
            args: Args {
                probe_type: "vfs_read".to_string(),
                duration: None,
                command: Some("cat".to_string()),
                verbose: false,
            },
            events: vec![
                events::typical_cat_reading_passwd(), // Should pass: matches command + valid
                events::editor_opening_config(),      // Should fail: wrong command
                FileReadEventBuilder::new() // Should fail: matches command but empty
                    .command("cat")
                            .build(),
                FileReadEventBuilder::new() // Should pass: partial match + valid
                    .command("concatenate")
                    .filename("/tmp/test")
                    .build(),
            ],
            expected_output_count: 2,
            description: "Should apply both command filtering and visibility rules",
        }
    }

    pub fn all_scenarios() -> Vec<TestScenario> {
        vec![
            no_filtering(),
            command_filtering(),
            verbose_mode_showing_empty_events(),
            normal_mode_hiding_empty_events(),
            mixed_filtering(),
        ]
    }
}

/// Utilities for testing formatting and output
pub mod formatting {
    use bee_trace::EventFormatter;

    use super::*;

    pub struct FormattingTestCase {
        pub name: &'static str,
        pub event: FileReadEvent,
        pub verbose: bool,
        pub expected_contains: Vec<&'static str>,
        pub expected_not_contains: Vec<&'static str>,
        pub max_length: Option<usize>,
    }

    pub fn standard_formatting_cases() -> Vec<FormattingTestCase> {
        vec![
            FormattingTestCase {
                name: "verbose_output_includes_uid",
                event: events::typical_cat_reading_passwd(),
                verbose: true,
                expected_contains: vec!["1234", "1000", "cat", "/etc/passwd"],
                expected_not_contains: vec!["..."],
                max_length: None,
            },
            FormattingTestCase {
                name: "non_verbose_excludes_uid",
                event: events::typical_cat_reading_passwd(),
                verbose: false,
                expected_contains: vec!["1234", "cat", "/etc/passwd"],
                expected_not_contains: vec!["1000", "..."], // UID not shown, no truncation
                max_length: Some(82),
            },
            FormattingTestCase {
                name: "long_filename_truncation_in_normal_mode",
                event: events::with_very_long_path(),
                verbose: false,
                expected_contains: vec!["4444", "longpathtool", "..."],
                expected_not_contains: vec![],
                max_length: Some(82),
            },
            FormattingTestCase {
                name: "long_filename_no_truncation_in_verbose_mode",
                event: events::with_very_long_path(),
                verbose: true,
                expected_contains: vec!["4444", "1000", "longpathtool", "/very/long/path"],
                expected_not_contains: vec!["..."],
                max_length: None,
            },
            FormattingTestCase {
                name: "unicode_path_handling",
                event: events::with_unicode_path(),
                verbose: false,
                expected_contains: vec!["3333", "cat", "🦀"],
                expected_not_contains: vec!["..."],
                max_length: Some(82),
            },
        ]
    }

    pub fn verify_formatting_case(test_case: &FormattingTestCase) -> Result<(), String> {
        let formatter = EventFormatter::new(test_case.verbose);
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
        pub operation: Box<dyn Fn() -> ()>,
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
            max_duration: Duration::from_millis(10),
        }
    }

    pub fn event_formatting_performance() -> PerformanceTest {
        PerformanceTest {
            name: "event_formatting",
            operation: Box::new(|| {
                let event = events::typical_cat_reading_passwd();
                let formatter = bee_trace::EventFormatter::new(false);
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
                let event = events::with_very_long_path();
                let _filename = event.filename_as_str();
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
            }
        }

        pub fn next_event(&mut self) -> FileReadEvent {
            self.pid_counter += 1;

            let command = self.commands.pop_front().unwrap_or("unknown");
            self.commands.push_back(command);

            let path = self.paths.pop_front().unwrap_or("/unknown");
            self.paths.push_back(path);

            FileReadEventBuilder::new()
                .pid(self.pid_counter)
                .uid(1000)
                .command(command)
                .filename(path)
                .build()
        }

        pub fn generate_batch(&mut self, count: usize) -> Vec<FileReadEvent> {
            (0..count).map(|_| self.next_event()).collect()
        }

        pub fn generate_with_pattern<F>(
            &mut self,
            count: usize,
            mut pattern: F,
        ) -> Vec<FileReadEvent>
        where
            F: FnMut(&mut FileReadEvent, usize),
        {
            (0..count)
                .map(|i| {
                    let mut event = self.next_event();
                    pattern(&mut event, i);
                    event
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
        let event = FileReadEventBuilder::new()
            .pid(1234)
            .command("test")
            .filename("/tmp/test")
            .build();

        assert_eq!(event.pid, 1234);
        assert_eq!(event.command_as_str(), "test");
        assert_eq!(event.filename_as_str(), "/tmp/test");
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
        for test_case in formatting::standard_formatting_cases() {
            assert!(formatting::verify_formatting_case(&test_case).is_ok());
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
