#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
use std::vec;

pub trait SecurityEventBuilder: Sized {
    fn with_pid(self, pid: u32) -> Self;
    fn with_uid(self, uid: u32) -> Self;
    fn with_command(self, command: &[u8]) -> Self;
}

pub trait SecurityEventData {
    fn pid(&self) -> u32;
    fn uid(&self) -> u32;
    fn command_as_str(&self) -> &str;
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetworkProtocol {
    TCP = 0,
    UDP = 1,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetworkAction {
    Allowed = 0,
    Blocked = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub dest_ip: [u8; 16], // IPv4 or IPv6 address
    pub dest_port: u16,
    pub protocol: u8, // Use NetworkProtocol enum in userspace
    pub is_ipv6: u8,
    pub action: u8, // Use NetworkAction enum in userspace
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

impl SecurityEventBuilder for NetworkEvent {
    fn with_pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }
}

impl SecurityEventData for NetworkEvent {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}

impl NetworkEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; 16],
            dest_ip: [0u8; 16],
            dest_port: 0,
            protocol: 0, // NetworkProtocol::TCP
            is_ipv6: 0,
            action: 0, // NetworkAction::Allowed
        }
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
        self.protocol = 0; // NetworkProtocol::TCP
        self
    }

    pub fn with_protocol_udp(mut self) -> Self {
        self.protocol = 1; // NetworkProtocol::UDP
        self
    }

    pub fn with_action_allowed(mut self) -> Self {
        self.action = 0; // NetworkAction::Allowed
        self
    }

    pub fn with_action_blocked(mut self) -> Self {
        self.action = 1; // NetworkAction::Blocked
        self
    }

    pub fn dest_ip_as_str(&self) -> &str {
        // TODO: convert ipv4 bits into human readable style(e.g. `111.111.111.111`).
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
    pub access_type: AccessType,
    pub path_or_var: [u8; 128], // file path or environment variable name
    pub path_len: usize,
}

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum AccessType {
    File = 0,
    EnvVar = 1,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SecretAccessEvent {}

impl SecurityEventBuilder for SecretAccessEvent {
    fn with_pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }
}

impl SecurityEventData for SecretAccessEvent {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}

impl SecretAccessEvent {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            comm: [0u8; 16],
            access_type: AccessType::File,
            path_or_var: [0u8; 128],
            path_len: 0,
        }
    }

    pub fn with_file_access(mut self, path: &[u8]) -> Self {
        self.access_type = AccessType::File;
        let copy_len = path.len().min(self.path_or_var.len());
        self.path_or_var[..copy_len].copy_from_slice(&path[..copy_len]);
        self.path_len = copy_len;
        self
    }

    pub fn with_env_var_access(mut self, var_name: &[u8]) -> Self {
        self.access_type = AccessType::EnvVar;
        let copy_len = var_name.len().min(self.path_or_var.len());
        self.path_or_var[..copy_len].copy_from_slice(&var_name[..copy_len]);
        self.path_len = copy_len;
        self
    }

    pub fn path_or_var_as_str(&self) -> &str {
        let end = self.path_len.min(self.path_or_var.len()) as usize;
        core::str::from_utf8(&self.path_or_var[..end]).unwrap_or("<invalid>")
    }

    pub fn access_type_as_str(&self) -> &str {
        match self.access_type {
            AccessType::File => "File",
            AccessType::EnvVar => "EnvVar",
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

impl SecurityEventBuilder for ProcessMemoryEvent {
    fn with_pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    fn with_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    fn with_command(mut self, command: &[u8]) -> Self {
        let copy_len = command.len().min(self.comm.len());
        self.comm[..copy_len].copy_from_slice(&command[..copy_len]);
        self
    }
}

impl SecurityEventData for ProcessMemoryEvent {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn command_as_str(&self) -> &str {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        core::str::from_utf8(&self.comm[..end]).unwrap_or("<invalid>")
    }
}

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
                assert_eq!(event.protocol, 0); // NetworkProtocol::TCP
                assert_eq!(event.is_ipv6, 0);
                assert_eq!(event.action, 0); // NetworkAction::Allowed
                assert_eq!(event.command_as_str(), "");
            }

            #[test]
            fn should_create_network_event_using_default_trait() {
                let event = NetworkEvent::default();

                assert_eq!(event.pid, 0);
                assert_eq!(event.protocol, 0); // NetworkProtocol::TCP
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
                assert_eq!(event.protocol, 0); // NetworkProtocol::TCP
                assert_eq!(event.action, 0); // NetworkAction::Allowed
                assert_eq!(event.protocol_as_str(), "TCP");
                assert_eq!(event.action_as_str(), "Allowed");
            }

            #[test]
            fn should_build_network_event_with_udp_connection() {
                let event = NetworkEvent::new()
                    .with_protocol_udp()
                    .with_action_blocked();

                assert_eq!(event.protocol, 1); // NetworkProtocol::UDP
                assert_eq!(event.action, 1); // NetworkAction::Blocked
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
                assert_eq!(event.access_type, AccessType::File);
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
                assert_eq!(event.access_type, AccessType::File);
                assert_eq!(event.path_len, file_path.len());
                assert_eq!(event.path_or_var_as_str(), "/etc/passwd");
                assert_eq!(event.access_type_as_str(), "File");
            }

            #[test]
            fn should_build_secret_access_event_for_env_var() {
                let var_name = b"SECRET_API_KEY";
                let event = SecretAccessEvent::new().with_env_var_access(var_name);

                assert_eq!(event.access_type, AccessType::EnvVar);
                assert_eq!(event.path_len, var_name.len());
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
}
