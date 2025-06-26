use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bee_trace::{Args, EventFormatter};
use bee_trace_common::FileReadEvent;

// Mock event processor for testing
struct MockEventProcessor {
    events: Arc<Mutex<VecDeque<String>>>,
}

impl MockEventProcessor {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn process_event(&self, event: &FileReadEvent, args: &Args, formatter: &EventFormatter) {
        // Apply the same logic as the real processor
        if !args.should_filter_event(event) {
            return;
        }

        if !args.should_show_event(event) {
            return;
        }

        let formatted = formatter.format_event(event);
        self.events.lock().unwrap().push_back(formatted);
    }

    fn get_processed_events(&self) -> Vec<String> {
        self.events.lock().unwrap().iter().cloned().collect()
    }

    fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

// Helper to create test events with different characteristics
mod test_event_factory {
    use super::*;

    pub fn create_cat_reading_passwd() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(1234)
            .with_uid(1000)
            .with_command(b"cat")
            .with_filename(b"/etc/passwd")
    }

    pub fn create_vim_reading_config() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(5678)
            .with_uid(1001)
            .with_command(b"vim")
            .with_filename(b"/home/user/.vimrc")
    }

    pub fn create_empty_read() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(9999)
            .with_uid(1000)
            .with_command(b"test")
            .with_filename(b"/tmp/empty")
    }

    pub fn create_no_filename() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(1111)
            .with_uid(1000)
            .with_command(b"mystery")
    }

    pub fn create_large_file_read() -> FileReadEvent {
        let long_path = format!("/very/long/path/to/some/deeply/nested/directory/structure/with/a/very/long/filename/that/exceeds/normal/length/limits/file_{}.txt", "x".repeat(50));
        FileReadEvent::new()
            .with_pid(2222)
            .with_uid(1000)
            .with_command(b"bigfilehandler")
            .with_filename(long_path.as_bytes())
    }

    pub fn create_system_process() -> FileReadEvent {
        FileReadEvent::new()
            .with_pid(1)
            .with_uid(0)
            .with_command(b"init")
            .with_filename(b"/proc/version")
    }
}

mod event_stream_processing {
    use test_event_factory::*;

    use super::*;

    #[test]
    fn should_process_valid_events_in_sequence() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        let events = vec![
            create_cat_reading_passwd(),
            create_vim_reading_config(),
            create_system_process(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 3);

        // Check that all events were formatted correctly
        assert!(processed[0].contains("cat"));
        assert!(processed[0].contains("/etc/passwd"));
        assert!(processed[1].contains("vim"));
        assert!(processed[1].contains(".vimrc"));
        assert!(processed[2].contains("init"));
    }

    #[test]
    fn should_filter_events_by_command() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: Some("cat".to_string()),
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        let events = vec![
            create_cat_reading_passwd(),
            create_vim_reading_config(),
            create_system_process(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1);
        assert!(processed[0].contains("cat"));
    }

    #[test]
    fn should_hide_empty_events_in_normal_mode() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        let events = vec![
            create_cat_reading_passwd(),
            create_empty_read(),
            create_no_filename(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 2); // cat and empty_read events (both have filenames)
        assert!(processed[0].contains("cat"));
    }

    #[test]
    fn should_show_all_events_in_verbose_mode() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: true,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(true);

        let events = vec![
            create_cat_reading_passwd(),
            create_empty_read(),
            create_no_filename(),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 3); // All events shown in verbose mode
    }

    #[test]
    fn should_handle_high_volume_event_stream() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        // Generate 1000 events
        let mut events = Vec::new();
        for i in 0..1000 {
            let mut event = create_cat_reading_passwd();
            event.pid = i; // Make each event unique
            events.push(event);
        }

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1000);

        // Verify that events are processed in order and correctly
        for (i, output) in processed.iter().enumerate() {
            assert!(output.contains(&i.to_string()));
        }
    }

    #[test]
    fn should_handle_mixed_filtering_scenarios() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: Some("cat".to_string()),
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        let events = vec![
            create_cat_reading_passwd(), // Should pass: matches command + valid
            create_vim_reading_config(), // Should fail: wrong command
            FileReadEvent::new() // Should fail: matches no command filter but empty
                .with_command(b"cat"),
            FileReadEvent::new() // Should pass: matches command + valid
                .with_command(b"concatenate")
                .with_filename(b"/tmp/test"),
        ];

        for event in &events {
            processor.process_event(event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 2);
        assert!(processed[0].contains("/etc/passwd"));
        assert!(processed[1].contains("concatenate"));
    }
}

mod performance_characteristics {
    use std::time::Instant;

    use test_event_factory::*;

    use super::*;

    #[test]
    fn should_process_events_efficiently() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        // Create a realistic event
        let event = create_cat_reading_passwd();

        let start = Instant::now();

        // Process 10,000 events
        for _ in 0..10_000 {
            processor.process_event(&event, &args, &formatter);
        }

        let duration = start.elapsed();

        // Processing should be fast (under 100ms for 10k events)
        assert!(
            duration.as_millis() < 100,
            "Event processing too slow: {:?}",
            duration
        );

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 10_000);
    }

    #[test]
    fn should_handle_memory_efficiently_with_large_filenames() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        // Process events with various filename lengths
        for _i in 0..100 {
            let event = create_large_file_read();
            processor.process_event(&event, &args, &formatter);
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 100);

        // All events should be processed and truncated appropriately
        for output in &processed {
            assert!(output.len() <= 82); // Non-verbose mode line limit
        }
    }
}

mod edge_case_handling {
    use test_event_factory::*;

    use super::*;

    #[test]
    fn should_handle_zero_values_gracefully() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: true, // Verbose to see all events
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(true);

        let zero_event = FileReadEvent::new(); // All zeros
        processor.process_event(&zero_event, &args, &formatter);

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1);

        let output = &processed[0];
        assert!(output.contains("0")); // PID should be 0
    }

    #[test]
    fn should_handle_maximum_values() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: true,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(true);

        let max_event = FileReadEvent::new()
            .with_pid(u32::MAX)
            .with_uid(u32::MAX)
            .with_command(b"maxcmd")
            .with_filename(b"/max/path");

        processor.process_event(&max_event, &args, &formatter);

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1);

        let output = &processed[0];
        assert!(output.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn should_handle_command_filter_edge_cases() {
        let processor = MockEventProcessor::new();

        // Test empty command filter
        let empty_filter_args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: Some("".to_string()),
            verbose: false,
            security_mode: false,
            config: None,
        };

        let event = create_cat_reading_passwd();
        processor.process_event(&event, &empty_filter_args, &EventFormatter::new(false));

        // Empty filter should match everything
        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1);

        processor.clear();

        // Test whitespace-only filter
        let whitespace_filter_args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: Some("   ".to_string()),
            verbose: false,
            security_mode: false,
            config: None,
        };

        processor.process_event(&event, &whitespace_filter_args, &EventFormatter::new(false));

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 0); // Should not match
    }

    #[test]
    fn should_handle_unicode_in_paths() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: true,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(true);

        let unicode_event = FileReadEvent::new()
            .with_pid(1234)
            .with_command(b"cat")
            .with_filename("🦀/rust/file.rs".as_bytes());

        processor.process_event(&unicode_event, &args, &formatter);

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1);

        let output = &processed[0];
        assert!(output.contains("🦀")); // Unicode should be preserved
    }
}

mod state_management {
    use test_event_factory::*;

    use super::*;

    #[test]
    fn should_maintain_state_across_multiple_processing_rounds() {
        let processor = MockEventProcessor::new();
        let args = Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        };
        let formatter = EventFormatter::new(false);

        // First round
        processor.process_event(&create_cat_reading_passwd(), &args, &formatter);
        assert_eq!(processor.get_processed_events().len(), 1);

        // Second round - should accumulate
        processor.process_event(&create_vim_reading_config(), &args, &formatter);
        assert_eq!(processor.get_processed_events().len(), 2);

        // Clear and start fresh
        processor.clear();
        assert_eq!(processor.get_processed_events().len(), 0);

        // Third round - should start from zero
        processor.process_event(&create_system_process(), &args, &formatter);
        assert_eq!(processor.get_processed_events().len(), 1);
    }

    #[test]
    fn should_handle_concurrent_processing_safely() {
        use std::{sync::Arc, thread};

        let processor = Arc::new(MockEventProcessor::new());
        let args = Arc::new(Args {
            probe_type: "vfs_read".to_string(),
            duration: None,
            command: None,
            verbose: false,
            security_mode: false,
            config: None,
        });
        let formatter = Arc::new(EventFormatter::new(false));

        let mut handles = vec![];

        // Spawn multiple threads processing events
        for i in 0..10 {
            let processor_clone = Arc::clone(&processor);
            let args_clone = Arc::clone(&args);
            let formatter_clone = Arc::clone(&formatter);

            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let mut event = create_cat_reading_passwd();
                    event.pid = (i * 100 + j) as u32; // Unique PID
                    processor_clone.process_event(&event, &args_clone, &formatter_clone);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let processed = processor.get_processed_events();
        assert_eq!(processed.len(), 1000); // 10 threads * 100 events each
    }
}
