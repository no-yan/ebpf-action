#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
use std::vec;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileReadEvent {
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; 64],
    pub filename_len: u32,
    pub comm: [u8; 16],
}

pub fn new_file_read_event(
    pid: u32,
    uid: u32,
    filename: [u8; 64],
    filename_len: u32,
    comm: [u8; 16],
) -> FileReadEvent {
    FileReadEvent {
        pid: pid,
        uid: uid,
        filename: filename,
        filename_len: filename_len,
        comm: comm,
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileReadEvent {}

impl FileReadEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            filename: [0u8; 64],
            filename_len: 0,
            comm: [0u8; 16],
        }
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    pub fn with_filename(mut self, filename: &[u8]) -> Self {
        let copy_len = filename.len().min(self.filename.len());
        self.filename[..copy_len].copy_from_slice(&filename[..copy_len]);
        self.filename_len = copy_len as u32;
        self
    }

    pub fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }

    pub fn filename_as_str(&self) -> &str {
        let end = self.filename_len.min(self.filename.len() as u32) as usize;
        core::str::from_utf8(&self.filename[..end]).unwrap_or("<invalid>")
    }

    pub fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}

impl Default for FileReadEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod file_read_event_creation {
        use super::*;

        #[test]
        fn should_create_event_with_default_values() {
            let event = FileReadEvent::new();

            assert_eq!(event.pid, 0);
            assert_eq!(event.uid, 0);
            assert_eq!(event.filename_len, 0);
            assert_eq!(event.filename_as_str(), "");
            assert_eq!(event.command_as_str(), "");
        }

        #[test]
        fn should_create_event_using_default_trait() {
            let event = FileReadEvent::default();

            assert_eq!(event.pid, 0);
            assert_eq!(event.uid, 0);
            assert_eq!(event.filename_len, 0);
        }
    }

    mod file_read_event_builder_pattern {
        use super::*;

        #[test]
        fn should_build_event_with_pid() {
            let event = FileReadEvent::new().with_pid(1234);

            assert_eq!(event.pid, 1234);
        }

        #[test]
        fn should_build_event_with_uid() {
            let event = FileReadEvent::new().with_uid(1000);

            assert_eq!(event.uid, 1000);
        }

        #[test]
        fn should_chain_builder_methods() {
            let event = FileReadEvent::new().with_pid(1234).with_uid(1000);

            assert_eq!(event.pid, 1234);
            assert_eq!(event.uid, 1000);
        }
    }

    mod file_read_event_filename_handling {
        use super::*;

        #[test]
        fn should_store_filename_correctly() {
            let filename = b"/etc/passwd";
            let event = FileReadEvent::new().with_filename(filename);

            assert_eq!(event.filename_len, filename.len() as u32);
            assert_eq!(event.filename_as_str(), "/etc/passwd");
        }

        #[test]
        fn should_truncate_long_filename() {
            let long_filename = vec![b'a'; 100]; // Longer than 64 bytes
            let event = FileReadEvent::new().with_filename(&long_filename);

            assert_eq!(event.filename_len, 64);
            assert_eq!(event.filename_as_str().len(), 64);
            assert!(event.filename_as_str().chars().all(|c| c == 'a'));
        }

        #[test]
        fn should_handle_empty_filename() {
            let event = FileReadEvent::new().with_filename(b"");

            assert_eq!(event.filename_len, 0);
            assert_eq!(event.filename_as_str(), "");
        }

        #[test]
        fn should_handle_filename_at_boundary() {
            let filename = vec![b'x'; 64]; // Exactly 64 bytes
            let event = FileReadEvent::new().with_filename(&filename);

            assert_eq!(event.filename_len, 64);
            assert_eq!(event.filename_as_str().len(), 64);
        }
    }

    mod file_read_event_command_handling {
        use super::*;

        #[test]
        fn should_store_command_correctly() {
            let command = b"cat";
            let event = FileReadEvent::new().with_command(command);

            assert_eq!(event.command_as_str(), "cat");
        }

        #[test]
        fn should_truncate_long_command() {
            let long_command = vec![b'b'; 20]; // Longer than 16 bytes
            let event = FileReadEvent::new().with_command(&long_command);

            assert_eq!(event.command_as_str().len(), 16);
        }

        #[test]
        fn should_handle_command_with_null_terminator() {
            let command = b"test\0\0\0\0".to_vec();
            let event = FileReadEvent::new().with_command(&command);

            assert_eq!(event.command_as_str(), "test");
        }

        #[test]
        fn should_handle_empty_command() {
            let event = FileReadEvent::new().with_command(b"");

            assert_eq!(event.command_as_str(), "");
        }
    }

    mod file_read_event_string_conversion {
        use super::*;

        #[test]
        fn should_handle_invalid_utf8_in_filename() {
            let mut event = FileReadEvent::new();
            event.filename[0] = 0xFF; // Invalid UTF-8
            event.filename[1] = 0xFE;
            event.filename_len = 2;

            assert_eq!(event.filename_as_str(), "<invalid>");
        }

        #[test]
        fn should_handle_invalid_utf8_in_command() {
            let mut event = FileReadEvent::new();
            event.comm[0] = 0xFF; // Invalid UTF-8
            event.comm[1] = 0xFE;

            assert_eq!(event.command_as_str(), "<invalid>");
        }

        #[test]
        fn should_respect_filename_length_field() {
            let mut event = FileReadEvent::new();
            event.filename[..5].copy_from_slice(b"hello");
            event.filename[5..10].copy_from_slice(b"world");
            event.filename_len = 5; // Only include "hello"

            assert_eq!(event.filename_as_str(), "hello");
        }

        #[test]
        fn should_handle_filename_length_exceeding_buffer() {
            let mut event = FileReadEvent::new();
            event.filename[..5].copy_from_slice(b"hello");
            event.filename_len = 100; // Larger than buffer

            let result = event.filename_as_str();
            // Should truncate to actual buffer content, but exact behavior may vary
            assert!(result.starts_with("hello"));
        }
    }

    mod file_read_event_memory_layout {
        use super::*;

        #[test]
        fn should_have_correct_size() {
            // Verify the structure size is reasonable for BPF stack usage
            // Size may vary by platform, but should be reasonable
            let size = core::mem::size_of::<FileReadEvent>();
            assert!(size <= 128, "Structure too large: {} bytes", size);
            assert!(size >= 88, "Structure unexpectedly small: {} bytes", size);
        }

        #[test]
        fn should_be_copy_and_clone() {
            let event = FileReadEvent::new().with_pid(123);
            let copied = event;
            let cloned = event.clone();

            assert_eq!(copied.pid, 123);
            assert_eq!(cloned.pid, 123);
        }
    }
}
