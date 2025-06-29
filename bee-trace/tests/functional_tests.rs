use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bee_trace::{Args, EventFormatter, SecurityEvent, TableFormatter};
use bee_trace_common::{SecretAccessEvent, SecurityEventBuilder};

// Mock event processor for testing SecurityEvent processing
struct MockSecurityEventProcessor {
    events: Arc<Mutex<VecDeque<String>>>,
}

impl MockSecurityEventProcessor {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn process_event(&self, event: &SecurityEvent, args: &Args, formatter: &TableFormatter) {
        // Apply the same logic as the real processor
        if !args.should_filter_security_event(event) {
            return;
        }

        if !args.should_show_security_event(event) {
            return;
        }

        let formatted = formatter.format_event(event);
        self.events.lock().unwrap().push_back(formatted);
    }

    fn get_processed_events(&self) -> Vec<String> {
        self.events.lock().unwrap().iter().cloned().collect()
    }
}

// Helper to create test security events
mod security_event_factory {
    use super::*;

    pub fn create_secret_file_access() -> SecurityEvent {
        let event = SecurityEventBuilder::with_command(
            SecurityEventBuilder::with_uid(
                SecurityEventBuilder::with_pid(SecretAccessEvent::new(), 1234),
                1000,
            ),
            b"cat",
        )
        .with_file_access(b"/etc/passwd");
        SecurityEvent::SecretAccess(event)
    }

    pub fn create_env_var_access() -> SecurityEvent {
        let event = SecurityEventBuilder::with_command(
            SecurityEventBuilder::with_uid(
                SecurityEventBuilder::with_pid(SecretAccessEvent::new(), 5678),
                1001,
            ),
            b"env",
        )
        .with_env_var_access(b"SECRET_API_KEY");
        SecurityEvent::SecretAccess(event)
    }

    pub fn create_config_file_access() -> SecurityEvent {
        let event = SecurityEventBuilder::with_command(
            SecurityEventBuilder::with_uid(
                SecurityEventBuilder::with_pid(SecretAccessEvent::new(), 9999),
                1000,
            ),
            b"vim",
        )
        .with_file_access(b"/home/user/.aws/credentials");
        SecurityEvent::SecretAccess(event)
    }
}

mod security_event_processing {
    use security_event_factory::*;

    use super::*;

    #[test]
    fn should_process_valid_security_events_in_sequence() {
        let processor = MockSecurityEventProcessor::new();
        let args = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: true,
            config: None,
        };
        let formatter = TableFormatter::new(false);

        let events = vec![
            create_secret_file_access(),
            create_env_var_access(),
            create_config_file_access(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 3);

        // Check that all events were formatted correctly
        assert!(processed[0].contains("cat"));
        assert!(processed[0].contains("SECRET_FILE"));
        assert!(processed[1].contains("env"));
        assert!(processed[1].contains("SECRET_ENV"));
        assert!(processed[2].contains("vim"));
        assert!(processed[2].contains("SECRET_FILE"));
    }

    #[test]
    fn should_filter_security_events_by_command() {
        let processor = MockSecurityEventProcessor::new();
        let args = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: Some("cat".to_string()),
            verbose: false,
            security_mode: true,
            config: None,
        };
        let formatter = TableFormatter::new(false);

        let events = vec![
            create_secret_file_access(),
            create_env_var_access(),
            create_config_file_access(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1); // Only the "cat" event should pass
        assert!(processed[0].contains("cat"));
    }

    #[test]
    fn should_show_all_events_in_security_mode() {
        let processor = MockSecurityEventProcessor::new();
        let args = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: true,
            config: None,
        };
        let formatter = TableFormatter::new(false);

        let events = vec![
            create_secret_file_access(),
            SecurityEvent::SecretAccess(SecretAccessEvent::new()), // Empty event
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 2); // Security mode shows all events
    }

    #[test]
    fn should_handle_high_volume_security_event_stream() {
        let processor = MockSecurityEventProcessor::new();
        let args = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: true,
            config: None,
        };
        let formatter = TableFormatter::new(false);

        // Generate 100 security events
        let mut events = Vec::new();
        for i in 0..100 {
            let event = SecurityEventBuilder::with_command(
                SecurityEventBuilder::with_pid(SecretAccessEvent::new(), i),
                b"test",
            )
            .with_file_access(b"/etc/passwd");
            events.push(SecurityEvent::SecretAccess(event));
        }

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 100);

        // Verify that events are processed correctly
        for (i, output) in processed.iter().enumerate() {
            assert!(output.contains(&i.to_string()));
        }
    }
}

mod performance_characteristics {
    use std::time::Instant;

    use security_event_factory::*;

    use super::*;

    #[test]
    fn should_process_security_events_efficiently() {
        let processor = MockSecurityEventProcessor::new();
        let args = Args {
            probe_type: "file_monitor".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: true,
            config: None,
        };
        let formatter = TableFormatter::new(false);

        // Create a realistic event
        let event = create_secret_file_access();

        let start = Instant::now();

        // Process 1,000 events
        for _ in 0..1_000 {
            processor.process_event(&event, &args, &formatter);
        }

        let duration = start.elapsed();

        // Processing should be fast (under 100ms for 1k events)
        assert!(
            duration.as_millis() < 100,
            "Security event processing too slow: {:?}",
            duration
        );

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1_000);
    }
}
