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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub dest_ip: [u8; 16], // IPv4 or IPv6 address
    pub dest_port: u16,
    pub protocol: u8, // 0 = TCP, 1 = UDP
    pub is_ipv6: u8,
    pub action: u8, // 0 = allowed, 1 = blocked
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

impl NetworkEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; 16],
            dest_ip: [0u8; 16],
            dest_port: 0,
            protocol: 0,
            is_ipv6: 0,
            action: 0,
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

    pub fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }

    pub fn with_dest_ipv4(mut self, ip: [u8; 4]) -> Self {
        self.dest_ip[..4].copy_from_slice(&ip);
        self.is_ipv6 = 0;
        self
    }

    pub fn with_dest_ipv6(mut self, ip: [u8; 16]) -> Self {
        self.dest_ip.copy_from_slice(&ip);
        self.is_ipv6 = 1;
        self
    }

    pub fn with_dest_port(mut self, port: u16) -> Self {
        self.dest_port = port;
        self
    }

    pub fn with_protocol_tcp(mut self) -> Self {
        self.protocol = 0;
        self
    }

    pub fn with_protocol_udp(mut self) -> Self {
        self.protocol = 1;
        self
    }

    pub fn with_action_allowed(mut self) -> Self {
        self.action = 0;
        self
    }

    pub fn with_action_blocked(mut self) -> Self {
        self.action = 1;
        self
    }

    pub fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    pub fn dest_ip_as_str(&self) -> &str {
        if self.is_ipv6 == 0 {
            // IPv4
            "<ipv4>"
        } else {
            // IPv6
            "<ipv6>"
        }
    }

    pub fn protocol_as_str(&self) -> &str {
        match self.protocol {
            0 => "TCP",
            1 => "UDP",
            _ => "Unknown",
        }
    }

    pub fn action_as_str(&self) -> &str {
        match self.action {
            0 => "Allowed",
            1 => "Blocked",
            _ => "Unknown",
        }
    }
}

impl Default for NetworkEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecretAccessEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub access_type: u8,        // 0 = file, 1 = env_var
    pub path_or_var: [u8; 128], // file path or environment variable name
    pub path_len: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecretAccessEvent {}

impl SecretAccessEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; 16],
            access_type: 0,
            path_or_var: [0u8; 128],
            path_len: 0,
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

    pub fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }

    pub fn with_file_access(mut self, path: &[u8]) -> Self {
        self.access_type = 0;
        let copy_len = path.len().min(self.path_or_var.len());
        self.path_or_var[..copy_len].copy_from_slice(&path[..copy_len]);
        self.path_len = copy_len as u32;
        self
    }

    pub fn with_env_var_access(mut self, var_name: &[u8]) -> Self {
        self.access_type = 1;
        let copy_len = var_name.len().min(self.path_or_var.len());
        self.path_or_var[..copy_len].copy_from_slice(&var_name[..copy_len]);
        self.path_len = copy_len as u32;
        self
    }

    pub fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    pub fn path_or_var_as_str(&self) -> &str {
        let end = self.path_len.min(self.path_or_var.len() as u32) as usize;
        core::str::from_utf8(&self.path_or_var[..end]).unwrap_or("<invalid>")
    }

    pub fn access_type_as_str(&self) -> &str {
        match self.access_type {
            0 => "File",
            1 => "EnvVar",
            _ => "Unknown",
        }
    }
}

impl Default for SecretAccessEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessMemoryEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub target_pid: u32,
    pub target_comm: [u8; 16],
    pub syscall_type: u8, // 0 = ptrace, 1 = process_vm_readv
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessMemoryEvent {}

impl ProcessMemoryEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; 16],
            target_pid: 0,
            target_comm: [0u8; 16],
            syscall_type: 0,
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

    pub fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }

    pub fn with_target_pid(mut self, target_pid: u32) -> Self {
        self.target_pid = target_pid;
        self
    }

    pub fn with_target_command(mut self, target_command: &[u8]) -> Self {
        let copy_len = target_command.len().min(self.target_comm.len());
        self.target_comm[..copy_len].copy_from_slice(&target_command[..copy_len]);
        self
    }

    pub fn with_ptrace(mut self) -> Self {
        self.syscall_type = 0;
        self
    }

    pub fn with_process_vm_readv(mut self) -> Self {
        self.syscall_type = 1;
        self
    }

    pub fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }

    pub fn target_command_as_str(&self) -> &str {
        let end = self
            .target_comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.target_comm.len());
        core::str::from_utf8(&self.target_comm[..end]).unwrap_or("<invalid>")
    }

    pub fn syscall_type_as_str(&self) -> &str {
        match self.syscall_type {
            0 => "ptrace",
            1 => "process_vm_readv",
            _ => "Unknown",
        }
    }
}

impl Default for ProcessMemoryEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod network_event_tests {
        use super::*;

        mod network_event_creation {
            use super::*;

            #[test]
            fn should_create_network_event_with_default_values() {
                let event = NetworkEvent::new();

                assert_eq!(event.pid, 0);
                assert_eq!(event.uid, 0);
                assert_eq!(event.dest_port, 0);
                assert_eq!(event.protocol, 0);
                assert_eq!(event.is_ipv6, 0);
                assert_eq!(event.action, 0);
                assert_eq!(event.command_as_str(), "");
            }

            #[test]
            fn should_create_network_event_using_default_trait() {
                let event = NetworkEvent::default();

                assert_eq!(event.pid, 0);
                assert_eq!(event.protocol, 0);
            }
        }

        mod network_event_builder_pattern {
            use super::*;

            #[test]
            fn should_build_network_event_with_tcp_connection() {
                let event = NetworkEvent::new()
                    .with_pid(1234)
                    .with_dest_port(443)
                    .with_protocol_tcp()
                    .with_action_allowed();

                assert_eq!(event.pid, 1234);
                assert_eq!(event.dest_port, 443);
                assert_eq!(event.protocol, 0); // TCP
                assert_eq!(event.action, 0); // Allowed
                assert_eq!(event.protocol_as_str(), "TCP");
                assert_eq!(event.action_as_str(), "Allowed");
            }

            #[test]
            fn should_build_network_event_with_udp_connection() {
                let event = NetworkEvent::new()
                    .with_protocol_udp()
                    .with_action_blocked();

                assert_eq!(event.protocol, 1); // UDP
                assert_eq!(event.action, 1); // Blocked
                assert_eq!(event.protocol_as_str(), "UDP");
                assert_eq!(event.action_as_str(), "Blocked");
            }

            #[test]
            fn should_build_network_event_with_ipv4_address() {
                let ipv4_addr = [192, 168, 1, 1];
                let event = NetworkEvent::new().with_dest_ipv4(ipv4_addr);

                assert_eq!(event.dest_ip[0], 192);
                assert_eq!(event.dest_ip[1], 168);
                assert_eq!(event.dest_ip[2], 1);
                assert_eq!(event.dest_ip[3], 1);
                assert_eq!(event.is_ipv6, 0);
            }

            #[test]
            fn should_build_network_event_with_ipv6_address() {
                let ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                let event = NetworkEvent::new().with_dest_ipv6(ipv6_addr);

                assert_eq!(event.dest_ip, ipv6_addr);
                assert_eq!(event.is_ipv6, 1);
            }
        }

        mod network_event_command_handling {
            use super::*;

            #[test]
            fn should_store_command_correctly() {
                let command = b"wget";
                let event = NetworkEvent::new().with_command(command);

                assert_eq!(event.command_as_str(), "wget");
            }

            #[test]
            fn should_truncate_long_command() {
                let long_command = vec![b'x'; 20]; // Longer than 16 bytes
                let event = NetworkEvent::new().with_command(&long_command);

                assert_eq!(event.command_as_str().len(), 16);
            }
        }
    }

    mod secret_access_event_tests {
        use super::*;

        mod secret_access_event_creation {
            use super::*;

            #[test]
            fn should_create_secret_access_event_with_default_values() {
                let event = SecretAccessEvent::new();

                assert_eq!(event.pid, 0);
                assert_eq!(event.uid, 0);
                assert_eq!(event.access_type, 0);
                assert_eq!(event.path_len, 0);
                assert_eq!(event.command_as_str(), "");
                assert_eq!(event.path_or_var_as_str(), "");
            }
        }

        mod secret_access_event_builder_pattern {
            use super::*;

            #[test]
            fn should_build_secret_access_event_for_file() {
                let file_path = b"/etc/passwd";
                let event = SecretAccessEvent::new()
                    .with_pid(1234)
                    .with_file_access(file_path);

                assert_eq!(event.pid, 1234);
                assert_eq!(event.access_type, 0); // File access
                assert_eq!(event.path_len, file_path.len() as u32);
                assert_eq!(event.path_or_var_as_str(), "/etc/passwd");
                assert_eq!(event.access_type_as_str(), "File");
            }

            #[test]
            fn should_build_secret_access_event_for_env_var() {
                let var_name = b"SECRET_API_KEY";
                let event = SecretAccessEvent::new().with_env_var_access(var_name);

                assert_eq!(event.access_type, 1); // Environment variable access
                assert_eq!(event.path_len, var_name.len() as u32);
                assert_eq!(event.path_or_var_as_str(), "SECRET_API_KEY");
                assert_eq!(event.access_type_as_str(), "EnvVar");
            }

            #[test]
            fn should_truncate_long_path() {
                let long_path = vec![b'a'; 150]; // Longer than 128 bytes
                let event = SecretAccessEvent::new().with_file_access(&long_path);

                assert_eq!(event.path_len, 128);
                assert_eq!(event.path_or_var_as_str().len(), 128);
            }
        }
    }

    mod process_memory_event_tests {
        use super::*;

        mod process_memory_event_creation {
            use super::*;

            #[test]
            fn should_create_process_memory_event_with_default_values() {
                let event = ProcessMemoryEvent::new();

                assert_eq!(event.pid, 0);
                assert_eq!(event.uid, 0);
                assert_eq!(event.target_pid, 0);
                assert_eq!(event.syscall_type, 0);
                assert_eq!(event.command_as_str(), "");
                assert_eq!(event.target_command_as_str(), "");
            }
        }

        mod process_memory_event_builder_pattern {
            use super::*;

            #[test]
            fn should_build_process_memory_event_with_ptrace() {
                let target_command = b"target_proc";
                let event = ProcessMemoryEvent::new()
                    .with_pid(1234)
                    .with_target_pid(5678)
                    .with_target_command(target_command)
                    .with_ptrace();

                assert_eq!(event.pid, 1234);
                assert_eq!(event.target_pid, 5678);
                assert_eq!(event.syscall_type, 0); // ptrace
                assert_eq!(event.target_command_as_str(), "target_proc");
                assert_eq!(event.syscall_type_as_str(), "ptrace");
            }

            #[test]
            fn should_build_process_memory_event_with_process_vm_readv() {
                let event = ProcessMemoryEvent::new().with_process_vm_readv();

                assert_eq!(event.syscall_type, 1); // process_vm_readv
                assert_eq!(event.syscall_type_as_str(), "process_vm_readv");
            }

            #[test]
            fn should_handle_unknown_syscall_type() {
                let mut event = ProcessMemoryEvent::new();
                event.syscall_type = 99; // Unknown type

                assert_eq!(event.syscall_type_as_str(), "Unknown");
            }
        }
    }

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
