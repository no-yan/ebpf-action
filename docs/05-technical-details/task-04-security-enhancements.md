# Task 04: Security Enhancements

**Priority:** HIGH  
**Estimated Time:** 10-15 hours  
**Complexity:** Medium-High  
**Dependencies:** Task 01 (Minor Fixes) - recommended to complete first  

## Overview

This task significantly enhances the security monitoring capabilities of bee-trace through comprehensive pattern expansion, network security hardening, and memory safety improvements. The focus is on practical security enhancements that strengthen detection capabilities while maintaining high performance.

## Current Security Gaps

### 1. Incomplete File Pattern Coverage
**Files:** `bee-trace-ebpf/src/file_monitor.rs:79-111`

Missing critical security file patterns:
- Cloud credentials: `.aws/credentials`, `.gcp/credentials.json`
- SSH configurations: `.ssh/config`, `.ssh/known_hosts`
- Container secrets: `docker/config.json`, `kubernetes/config`
- Enterprise certificates: `*.p8`, `*.pkcs12`, `*.jks`
- Security vaults: `vault/*`, `secrets/*`

### 2. Network Security Weaknesses
**Files:** `bee-trace-ebpf/src/network.rs:65-69`, `bee-trace-common/src/lib.rs:138-147`

Current limitations:
- No IPv6 address validation or parsing
- Missing TLS/SSL certificate monitoring
- Limited network event correlation
- Incomplete blocked IP handling for IPv6

### 3. Memory Safety Concerns
**Files:** `bee-trace-ebpf/src/file_monitor.rs:34-36`, `bee-trace-ebpf/src/network.rs:33`

Potential vulnerabilities:
- Insufficient bounds checking in string operations
- Missing stack overflow protection
- Limited validation of kernel data structures

## Proposed Enhancements

### 1. File Monitor Pattern Expansion

**File:** `bee-trace-ebpf/src/file_monitor.rs`

#### Enhanced Sensitive File Detection

```rust
#[inline(never)]
unsafe fn is_sensitive_file(filename: &[u8; 128], len: usize) -> bool {
    if len == 0 || len > 128 {
        return false;
    }

    // Core security files (existing + new)
    if filename.starts_with(b"credentials.json")
        | filename.starts_with(b"id_rsa")
        | filename.starts_with(b"id_dsa")
        | filename.starts_with(b"id_ecdsa")
        | filename.starts_with(b"id_ed25519")
        | filename.starts_with(b".env")
        | filename.starts_with(b"config.json")
        | filename.starts_with(b"secrets.yaml")  // Fixed typo
        | filename.starts_with(b"secrets.yml")
        | filename.starts_with(b"private.key")
    {
        return true;
    }

    // NEW: Cloud provider credentials
    if filename.starts_with(b".aws/credentials")
        | filename.starts_with(b".aws/config")
        | filename.starts_with(b".gcp/credentials.json")
        | filename.starts_with(b".azure/credentials")
        | filename.starts_with(b"gcloud/credentials.db")
    {
        return true;
    }

    // NEW: SSH and network configuration
    if filename.starts_with(b".ssh/config")
        | filename.starts_with(b".ssh/known_hosts")
        | filename.starts_with(b".ssh/authorized_keys")
        | filename.starts_with(b"ssh_host_rsa_key")
        | filename.starts_with(b"ssh_host_ecdsa_key")
        | filename.starts_with(b"ssh_host_ed25519_key")
    {
        return true;
    }

    // NEW: Container and orchestration secrets
    if filename.starts_with(b"docker/config.json")
        | filename.starts_with(b".docker/config.json")
        | filename.starts_with(b"kubernetes/config")
        | filename.starts_with(b".kube/config")
        | filename.starts_with(b"kubeconfig")
    {
        return true;
    }

    // NEW: Security vault and secrets management
    if filename.starts_with(b"vault/")
        | filename.starts_with(b"secrets/")
        | filename.starts_with(b".vault-token")
        | filename.starts_with(b"consul.json")
    {
        return true;
    }

    // Enhanced extension checks with better bounds validation
    if len >= 4 {
        let start = len.saturating_sub(4); // Use saturating_sub for safety
        if start < 124 {
            let ext = &filename[start..start + 4];
            if ext == b".pem"
                || ext == b".key"
                || ext == b".p12"
                || ext == b".pfx"
                || ext == b".crt"
                || ext == b".cer"
                || ext == b".der"
                || ext == b".p8k"  // NEW: PKCS#8 key
                || ext == b".jks"  // NEW: Java KeyStore
            {
                return true;
            }
        }
    }

    // NEW: Extended certificate formats
    if len >= 5 {
        let start = len.saturating_sub(5);
        if start < 123 {
            let ext = &filename[start..start + 5];
            if ext == b".pkcs" {
                return true;
            }
        }
    }

    // NEW: Extended certificate formats (6 chars)
    if len >= 6 {
        let start = len.saturating_sub(6);
        if start < 122 {
            let ext = &filename[start..start + 6];
            if ext == b".pkcs8" || ext == b".pkcs12" {
                return true;
            }
        }
    }

    // NEW: Check for certificate directories
    if is_certificate_directory(filename, len) {
        return true;
    }

    false
}

// NEW: Helper function for certificate directory detection
#[inline]
unsafe fn is_certificate_directory(filename: &[u8; 128], len: usize) -> bool {
    // Common certificate directory patterns
    let cert_dirs = [
        b"/etc/ssl/",
        b"/etc/pki/",
        b"/usr/share/ca-certificates/",
        b"/etc/ca-certificates/",
    ];

    for dir_pattern in cert_dirs.iter() {
        if len >= dir_pattern.len() {
            let mut matches = true;
            for (i, &byte) in dir_pattern.iter().enumerate() {
                if filename[i] != byte {
                    matches = false;
                    break;
                }
            }
            if matches {
                return true;
            }
        }
    }
    false
}
```

#### Enhanced File Access Logging

```rust
// Enhanced debug logging with bounds checking
if let Ok(filename) = str::from_utf8(&filename_buf[..filename_len.min(128) as usize]) {
    info!(&ctx, "monitoring sensitive file access: {}", filename);
} else {
    warn!(&ctx, "failed to parse filename as UTF-8, raw bytes logged");
}
```

### 2. Network Security Hardening

**File:** `bee-trace-ebpf/src/network.rs`

#### Enhanced IPv6 Support and Validation

```rust
unsafe fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *const sock = ctx.arg::<*const sock>(0).ok_or(1i64)?;
    if sock.is_null() {
        return Ok(0);
    }

    let sk_common: sock_common = bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)?;

    let family = i32::from(sk_common.skc_family);
    
    // Validate address family
    if family != AF_INET && family != AF_INET6 {
        return Ok(0); // Skip unsupported address families
    }

    let mut event = NetworkEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm: ctx.command().unwrap_or_default(),
        dest_ip: [0u8; 16],
        dest_port: sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport
            .to_be(),
        protocol: 0, // NetworkProtocol::TCP
        is_ipv6: if family == AF_INET6 { 1 } else { 0 },
        action: 0, // NetworkAction::Allowed
        security_flags: 0, // NEW: Security classification flags
    };

    if family == AF_INET {
        // Enhanced IPv4 handling with validation
        let dest_ip = sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_daddr;
        
        // Validate IPv4 address (not all zeros, not broadcast)
        if dest_ip != 0 && dest_ip != 0xFFFFFFFF {
            event.dest_ip[0..4].copy_from_slice(&dest_ip.to_be_bytes());
            
            // Enhanced blocking logic with security classification
            if BLOCKED_IPS.get(&dest_ip).is_some() {
                event.action = 1; // NetworkAction::Blocked
                event.security_flags |= SECURITY_FLAG_BLOCKED_IP;
            }
            
            // NEW: Classify suspicious destinations
            if is_suspicious_ipv4_destination(dest_ip) {
                event.security_flags |= SECURITY_FLAG_SUSPICIOUS_DEST;
            }
        }
    } else if family == AF_INET6 {
        // Enhanced IPv6 handling with proper validation
        let dest_ip = sk_common.skc_v6_daddr.in6_u.u6_addr8;
        
        // Validate IPv6 address (not all zeros)
        if !is_ipv6_zero(&dest_ip) {
            event.dest_ip.copy_from_slice(&dest_ip);
            
            // NEW: IPv6 blocking support
            if is_blocked_ipv6(&dest_ip) {
                event.action = 1; // NetworkAction::Blocked
                event.security_flags |= SECURITY_FLAG_BLOCKED_IP;
            }
            
            // NEW: IPv6 security classification
            if is_suspicious_ipv6_destination(&dest_ip) {
                event.security_flags |= SECURITY_FLAG_SUSPICIOUS_DEST;
            }
        }
    }

    NETWORK_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// NEW: IPv6 validation helpers
#[inline]
fn is_ipv6_zero(addr: &[u8; 16]) -> bool {
    addr.iter().all(|&b| b == 0)
}

#[inline]
fn is_blocked_ipv6(addr: &[u8; 16]) -> bool {
    // Check against IPv6 blocklist (would need implementation)
    // For now, return false - could be extended with actual blocklist
    false
}

// NEW: Security classification functions
#[inline]
fn is_suspicious_ipv4_destination(ip: u32) -> bool {
    let bytes = ip.to_be_bytes();
    
    // Private ranges are generally less suspicious for outbound
    // Flag public IPs on suspicious ports as more interesting
    let is_private = 
        (bytes[0] == 10) ||  // 10.0.0.0/8
        (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||  // 172.16.0.0/12
        (bytes[0] == 192 && bytes[1] == 168);  // 192.168.0.0/16

    !is_private  // Public IPs are more suspicious
}

#[inline]
fn is_suspicious_ipv6_destination(addr: &[u8; 16]) -> bool {
    // Link-local: fe80::/10
    if addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80 {
        return false;  // Link-local is normal
    }
    
    // Unique local: fc00::/7  
    if (addr[0] & 0xfe) == 0xfc {
        return false;  // Unique local is normal
    }
    
    // Everything else is potentially more interesting
    true
}
```

#### TLS/SSL Certificate Monitoring Hook

```rust
// NEW: Certificate validation monitoring
#[kprobe]
pub fn ssl_cert_verify(ctx: ProbeContext) -> u32 {
    unsafe { try_ssl_cert_verify(ctx) }.unwrap_or(1)
}

unsafe fn try_ssl_cert_verify(ctx: ProbeContext) -> Result<u32, i64> {
    // This would require additional kernel symbol access
    // Placeholder for TLS certificate monitoring
    let event = NetworkEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm: ctx.command().unwrap_or_default(),
        dest_ip: [0u8; 16],
        dest_port: 0,
        protocol: 0,
        is_ipv6: 0,
        action: 0,
        security_flags: SECURITY_FLAG_TLS_CERT_VALIDATION,
    };

    NETWORK_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}
```

**File:** `bee-trace-common/src/lib.rs`

#### Enhanced Network Event Structure

```rust
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
    pub security_flags: u8, // NEW: Security classification flags
}

// NEW: Security flag constants
pub const SECURITY_FLAG_BLOCKED_IP: u8 = 0x01;
pub const SECURITY_FLAG_SUSPICIOUS_DEST: u8 = 0x02;
pub const SECURITY_FLAG_TLS_CERT_VALIDATION: u8 = 0x04;
pub const SECURITY_FLAG_HIGH_RISK_PORT: u8 = 0x08;

impl NetworkEvent {
    // Enhanced IP address formatting with proper IPv6 support
    pub fn dest_ip_as_str(&self) -> alloc::string::String {
        if self.is_ipv6 == 0 {
            // IPv4 - convert to dotted decimal notation
            format!("{}.{}.{}.{}", 
                self.dest_ip[0], 
                self.dest_ip[1], 
                self.dest_ip[2], 
                self.dest_ip[3]
            )
        } else {
            // IPv6 - convert to colon-hexadecimal notation
            format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                self.dest_ip[0], self.dest_ip[1], self.dest_ip[2], self.dest_ip[3],
                self.dest_ip[4], self.dest_ip[5], self.dest_ip[6], self.dest_ip[7],
                self.dest_ip[8], self.dest_ip[9], self.dest_ip[10], self.dest_ip[11],
                self.dest_ip[12], self.dest_ip[13], self.dest_ip[14], self.dest_ip[15]
            )
        }
    }

    // NEW: Security classification methods
    pub fn is_blocked(&self) -> bool {
        (self.security_flags & SECURITY_FLAG_BLOCKED_IP) != 0
    }

    pub fn is_suspicious(&self) -> bool {
        (self.security_flags & SECURITY_FLAG_SUSPICIOUS_DEST) != 0
    }

    pub fn has_tls_validation(&self) -> bool {
        (self.security_flags & SECURITY_FLAG_TLS_CERT_VALIDATION) != 0
    }

    pub fn security_classification(&self) -> &str {
        if self.is_blocked() {
            "BLOCKED"
        } else if self.is_suspicious() {
            "SUSPICIOUS" 
        } else if self.has_tls_validation() {
            "TLS_MONITORED"
        } else {
            "NORMAL"
        }
    }
}
```

### 3. Memory Safety Improvements

**File:** `bee-trace-ebpf/src/file_monitor.rs`

#### Enhanced Bounds Checking and Stack Protection

```rust
// Enhanced filename reading with comprehensive bounds checking
unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    // Get the filename from the tracepoint arguments
    let filename_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;

    if filename_ptr.is_null() {
        return Ok(0);
    }

    // Stack protection: Use smaller buffer and validate size
    let mut filename_buf = [0u8; 128]; // Keep 128 but add protections
    
    // Enhanced bounds checking with error recovery
    let filename_result = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf);
    
    let filename_len = match filename_result {
        Ok(bytes_read) => {
            // Validate the length is reasonable
            let len = bytes_read.len();
            if len == 0 {
                return Ok(0); // Empty filename, nothing to monitor
            }
            if len > 127 {
                // Truncate but continue processing - this is suspicious
                warn!(&ctx, "filename truncated due to excessive length: {}", len);
                127
            } else {
                len
            }
        }
        Err(_) => {
            // Failed to read filename - could indicate attack or kernel issue
            warn!(&ctx, "failed to read filename from user space");
            return Ok(0);
        }
    };

    // Additional validation: Check for null bytes in unexpected places
    if has_embedded_nulls(&filename_buf, filename_len) {
        warn!(&ctx, "detected embedded null bytes in filename - potential security issue");
        // Continue processing but flag as suspicious
    }

    // Enhanced filename parsing with error recovery
    match str::from_utf8(&filename_buf[..filename_len]) {
        Ok(filename) => {
            info!(&ctx, "monitoring file access: {}", filename);
        }
        Err(utf8_error) => {
            // Log the specific UTF-8 error for debugging
            warn!(&ctx, "failed to parse filename as UTF-8 at byte {}: {:?}", 
                  utf8_error.valid_up_to(), 
                  &filename_buf[..filename_len.min(32)]); // Log first 32 bytes safely
        }
    }

    // Enhanced sensitivity check with bounds validation
    if !is_sensitive_file_safe(&filename_buf, filename_len) {
        return Ok(0);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    // Enhanced event creation with validation
    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: bee_trace_common::AccessType::File,
        path_or_var: [0u8; 128],
        path_len: filename_len.min(128) as u32, // Ensure we don't exceed buffer
    };

    // Safe copying with explicit bounds checking
    let copy_len = filename_len.min(event.path_or_var.len());
    if copy_len > 0 {
        event.path_or_var[..copy_len].copy_from_slice(&filename_buf[..copy_len]);
    }

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// NEW: Enhanced validation functions
#[inline]
fn has_embedded_nulls(buffer: &[u8; 128], len: usize) -> bool {
    if len == 0 {
        return false;
    }
    
    // Check for null bytes before the expected end
    for i in 0..len.min(127) {  // Check up to len-1 or 126, whichever is smaller
        if buffer[i] == 0 {
            return true;
        }
    }
    false
}

// Enhanced sensitivity check with comprehensive bounds validation
#[inline(never)]
unsafe fn is_sensitive_file_safe(filename: &[u8; 128], len: usize) -> bool {
    // Comprehensive input validation
    if len == 0 || len > 128 {
        return false;
    }

    // Ensure we don't access beyond the valid data   
    let safe_len = len.min(128);
    
    // Use the enhanced sensitivity check from section 1
    is_sensitive_file(filename, safe_len)
}
```

**File:** `bee-trace-ebpf/src/memory.rs`

#### Enhanced Memory Access Monitoring

```rust
// Enhanced stack overflow protection for memory monitoring
#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_ptrace_safe(ctx) }.unwrap_or_else(|error_code| {
        warn!(&ctx, "ptrace monitoring failed with error: {}", error_code);
        1
    })
}

unsafe fn try_sys_enter_ptrace_safe(ctx: TracePointContext) -> Result<u32, i64> {
    // Stack protection: minimize stack usage
    let target_pid: u32 = ctx.read_at(16)?; // PTRACE_ATTACH typically has pid at offset 16
    
    // Validate PID is reasonable (not 0, not too large)
    if target_pid == 0 || target_pid > 65536 {
        // Suspicious PID, log but allow
        warn!(&ctx, "ptrace called with suspicious PID: {}", target_pid);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    // Get target process info safely
    let target_comm = get_target_process_comm_safe(target_pid);

    let event = ProcessMemoryEvent {
        pid: ctx.pid(),
        uid: ctx.uid(), 
        comm,
        target_pid,
        target_comm,
        syscall_type: 0, // ptrace
    };

    PROCESS_MEMORY_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// NEW: Safe target process communication retrieval
#[inline]
unsafe fn get_target_process_comm_safe(target_pid: u32) -> [u8; 16] {
    let mut comm = [0u8; 16];
    
    // This would require additional kernel helpers to safely get process info
    // For now, we'll return a safe default and mark it as unknown
    let unknown = b"<unknown>";
    let copy_len = unknown.len().min(comm.len());
    comm[..copy_len].copy_from_slice(&unknown[..copy_len]);
    
    comm
}
```

## Implementation Steps

### Phase 1: File Monitor Pattern Expansion (3-4 hours)
1. **Update File Pattern Recognition**
   - Modify `bee-trace-ebpf/src/file_monitor.rs:is_sensitive_file()`
   - Add cloud provider credential patterns
   - Add container and orchestration secrets
   - Add certificate directory detection
   - Fix typo in "secrerts.yaml"

2. **Add Extended Certificate Format Support**
   - Add PKCS#8, PKCS#12, JKS format detection
   - Add 5 and 6 character extension support
   - Implement certificate directory scanning

3. **Test Pattern Recognition**
   ```bash
   # Create test files for new patterns
   mkdir -p test_files/.aws test_files/.ssh test_files/docker
   touch test_files/.aws/credentials
   touch test_files/.ssh/config  
   touch test_files/docker/config.json
   touch test_files/test.pkcs12
   
   # Test detection
   just run-file-monitor --duration 10 --verbose
   ```

### Phase 2: Network Security Hardening (4-5 hours)
1. **Enhance IPv6 Support**
   - Update `bee-trace-ebpf/src/network.rs` with IPv6 validation
   - Add proper IPv6 address parsing and formatting
   - Implement IPv6 blocking support

2. **Add Security Classification**
   - Extend `NetworkEvent` structure with security flags
   - Implement suspicious destination detection
   - Add network event correlation logic

3. **Update Network Event Processing**
   - Modify `bee-trace-common/src/lib.rs` 
   - Add IP address formatting methods
   - Add security classification methods

### Phase 3: Memory Safety Improvements (3-4 hours)  
1. **Enhanced Bounds Checking**
   - Update all string operations with saturating arithmetic
   - Add comprehensive validation in file monitor
   - Implement safe buffer handling patterns

2. **Stack Overflow Protection**
   - Reduce stack usage in critical functions
   - Add buffer size validation
   - Implement safe error recovery patterns

3. **Kernel Data Validation**
   - Add validation for all kernel structure reads
   - Implement safe defaults for failed operations
   - Add comprehensive error logging

### Phase 4: Testing and Validation (2-3 hours)
1. **Security Pattern Testing**
   ```bash
   # Test all new file patterns
   ./scripts/test-security-patterns.sh
   
   # Test network security features  
   ./scripts/test-network-security.sh
   
   # Test memory safety improvements
   ./scripts/test-memory-safety.sh
   ```

2. **Performance Validation**
   ```bash
   # Benchmark before and after changes
   cargo bench --features benchmark
   
   # Memory usage testing
   valgrind --tool=memcheck target/release/bee-trace --duration 30
   ```

3. **Integration Testing**
   ```bash
   # Full system testing
   cargo test --all-features
   just run-all-monitors --duration 60 --verbose
   ```

## Enhanced Testing Strategy

### Security Pattern Tests

**New File:** `bee-trace/tests/security_pattern_tests.rs`

```rust
#[cfg(test)]
mod security_pattern_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn should_detect_cloud_provider_credentials() {
        let test_patterns = vec![
            ".aws/credentials",
            ".aws/config", 
            ".gcp/credentials.json",
            ".azure/credentials",
            "gcloud/credentials.db",
        ];

        for pattern in test_patterns {
            // Test pattern detection logic
            assert!(is_sensitive_cloud_file(pattern.as_bytes()));
        }
    }

    #[test]
    fn should_detect_container_secrets() {
        let test_patterns = vec![
            "docker/config.json",
            ".docker/config.json",
            "kubernetes/config",
            ".kube/config",
            "kubeconfig",
        ];

        for pattern in test_patterns {
            assert!(is_sensitive_container_file(pattern.as_bytes()));
        }
    }

    #[test]
    fn should_detect_extended_certificate_formats() {
        let test_patterns = vec![
            "cert.pkcs8",
            "key.pkcs12", 
            "keystore.jks",
            "certificate.p8k",
        ];

        for pattern in test_patterns {
            assert!(is_sensitive_certificate_file(pattern.as_bytes()));
        }
    }

    #[tokio::test]
    async fn should_monitor_real_file_access() {
        let temp_dir = TempDir::new().unwrap();
        let secret_file = temp_dir.path().join(".aws").join("credentials");
        
        fs::create_dir_all(secret_file.parent().unwrap()).unwrap();
        fs::write(&secret_file, "aws_access_key_id=test").unwrap();

        // This would require integration with actual eBPF monitoring
        // For now, verify the file exists and would be detected
        assert!(secret_file.exists());
    }
}
```

### Network Security Tests

**New File:** `bee-trace/tests/network_security_tests.rs`

```rust
#[cfg(test)]
mod network_security_tests {
    use super::*;
    use bee_trace_common::{NetworkEvent, SECURITY_FLAG_SUSPICIOUS_DEST};

    #[test]
    fn should_format_ipv4_addresses_correctly() {
        let event = NetworkEvent::new()
            .with_dest_ipv4([192, 168, 1, 1])
            .with_dest_port(443);

        assert_eq!(event.dest_ip_as_str(), "192.168.1.1");
        assert_eq!(event.dest_port, 443);
    }

    #[test]
    fn should_format_ipv6_addresses_correctly() {
        let ipv6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let event = NetworkEvent::new().with_dest_ipv6(ipv6_addr);

        let formatted = event.dest_ip_as_str();
        assert!(formatted.contains("2001:0db8"));
        assert_eq!(event.is_ipv6, 1);
    }

    #[test]
    fn should_classify_suspicious_destinations() {
        let mut event = NetworkEvent::new()
            .with_dest_ipv4([8, 8, 8, 8]); // Public DNS - suspicious for some contexts
        
        event.security_flags = SECURITY_FLAG_SUSPICIOUS_DEST;
        
        assert!(event.is_suspicious());
        assert_eq!(event.security_classification(), "SUSPICIOUS");
    }

    #[test]
    fn should_handle_blocked_ips() {
        let mut event = NetworkEvent::new()
            .with_dest_ipv4([10, 0, 0, 1]);
        
        event.security_flags = SECURITY_FLAG_BLOCKED_IP;
        
        assert!(event.is_blocked());
        assert_eq!(event.security_classification(), "BLOCKED");
    }
}
```

### Memory Safety Tests

**New File:** `bee-trace/tests/memory_safety_tests.rs`

```rust
#[cfg(test)]
mod memory_safety_tests {
    use super::*;

    #[test]
    fn should_handle_oversized_filenames_safely() {
        let oversized_name = vec![b'x'; 200]; // Larger than 128 byte buffer
        
        // This should not panic or cause buffer overflow
        let result = validate_filename_safe(&oversized_name);
        assert!(result.is_ok());
        assert!(result.unwrap().len() <= 128);
    }

    #[test]
    fn should_detect_embedded_null_bytes() {
        let malicious_name = b"normal_file\0hidden_payload";
        
        assert!(has_embedded_nulls_in_slice(malicious_name));
    }

    #[test]
    fn should_safely_parse_invalid_utf8() {
        let invalid_utf8 = [0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
        
        // Should not panic, should return safe default
        let result = safe_utf8_parse(&invalid_utf8);
        assert_eq!(result, "<invalid>");
    }

    #[test]
    fn should_validate_network_addresses() {
        // Test IPv4 validation
        assert!(is_valid_ipv4_address([192, 168, 1, 1]));
        assert!(!is_valid_ipv4_address([0, 0, 0, 0])); // Invalid all-zeros
        
        // Test IPv6 validation  
        let valid_ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let zero_ipv6 = [0u8; 16];
        
        assert!(is_valid_ipv6_address(&valid_ipv6));
        assert!(!is_valid_ipv6_address(&zero_ipv6));
    }
}
```

## Acceptance Criteria

### File Monitor Enhancements
- [ ] All specified cloud provider credential patterns detected (.aws/credentials, .gcp/credentials.json, etc.)
- [ ] Container secret patterns properly recognized (docker/config.json, kubernetes/config)
- [ ] Extended certificate formats supported (*.pkcs8, *.pkcs12, *.jks, *.p8k)
- [ ] Certificate directory monitoring implemented (/etc/ssl/, /etc/pki/)
- [ ] Typo in "secrerts.yaml" fixed to "secrets.yaml"
- [ ] All file pattern tests pass with >95% coverage

### Network Security Hardening
- [ ] IPv6 addresses properly parsed and formatted in human-readable form
- [ ] IPv6 blocking support implemented and tested
- [ ] Security classification system working (NORMAL/SUSPICIOUS/BLOCKED)
- [ ] Network event correlation logic implemented
- [ ] TLS/SSL certificate monitoring hooks prepared (even if not fully active)
- [ ] All network security tests pass

### Memory Safety Improvements
- [ ] All string operations use saturating arithmetic for bounds checking
- [ ] Buffer overflow protection implemented in all critical paths
- [ ] Enhanced validation for all kernel structure reads
- [ ] Safe error recovery implemented for failed operations
- [ ] Comprehensive error logging added for debugging
- [ ] Memory safety tests pass without valgrind errors

### Performance and Compatibility
- [ ] No performance regression >5% in event processing
- [ ] All existing tests continue to pass
- [ ] eBPF programs compile successfully on target kernels
- [ ] Memory usage remains within acceptable limits
- [ ] No new compiler warnings introduced

## Risk Assessment

**Risk Level:** MEDIUM-HIGH

### Technical Risks
- **High Complexity:** Multiple subsystem changes requiring careful coordination
- **eBPF Constraints:** Kernel verifier limitations may restrict some enhancements
- **Performance Impact:** Additional pattern matching and validation may affect performance
- **Memory Usage:** Enhanced structures may increase memory footprint

### Security Risks
- **False Positives:** More aggressive pattern matching may increase false positive rate
- **Bypass Potential:** Attackers might find ways around new pattern detection
- **Kernel Stability:** Enhanced kernel probing might affect system stability

### Mitigation Strategies
- **Incremental Implementation:** Roll out changes in phases to isolate issues
- **Comprehensive Testing:** Extensive unit, integration, and performance testing
- **Fallback Mechanisms:** Safe defaults and error recovery for all new features
- **Documentation:** Clear documentation of all changes and their security implications

## Performance Considerations

### Expected Impact
- **File Pattern Matching:** +10-15% CPU usage due to extended pattern checking
- **Network Processing:** +5-10% overhead from IPv6 validation and security classification  
- **Memory Usage:** +20-30% due to enhanced event structures and validation
- **I/O Impact:** Minimal, as monitoring is passive

### Optimization Strategies
- **Pattern Matching:** Use efficient string algorithms, early termination
- **Memory Management:** Pool buffer allocation, minimize stack usage
- **Caching:** Cache pattern matching results where possible
- **Conditional Compilation:** Allow disabling features for performance-critical deployments

## Dependencies and Prerequisites

### Required Before Starting
- [ ] Task 01 (Minor Fixes) completed - reduces merge conflicts
- [ ] Development environment setup with latest tools
- [ ] Kernel headers and eBPF development tools installed
- [ ] Test environment prepared with various file types

### External Dependencies
- **Kernel Version:** Linux 5.4+ for full IPv6 eBPF support
- **eBPF Features:** BTF (BPF Type Format) support for enhanced debugging
- **Build Tools:** Latest bpf-linker for extended eBPF program size
- **Testing Tools:** Network simulation tools for network security testing

## Future Enhancements

This task provides foundation for future security enhancements:

### Short Term (Next 2-3 months)
- **Machine Learning Integration:** Pattern recognition for anomaly detection
- **Threat Intelligence:** Integration with threat feed APIs
- **Real-time Alerting:** Integration with security information systems

### Medium Term (3-6 months)
- **Behavioral Analysis:** Process behavior profiling and anomaly detection
- **Network Flow Analysis:** Deep packet inspection capabilities
- **Container Security:** Enhanced container runtime monitoring

### Long Term (6+ months)
- **Zero Trust Integration:** Integration with zero trust security frameworks
- **Cloud Security:** Enhanced cloud-native security monitoring
- **Compliance Reporting:** Automated compliance and audit reporting

## Success Metrics

### Quantitative Metrics
- **Detection Coverage:** 95%+ of common sensitive file patterns detected
- **False Positive Rate:** <5% for file pattern detection
- **Performance Impact:** <15% CPU overhead increase
- **Memory Usage:** <30% memory footprint increase
- **Test Coverage:** >95% code coverage for all new functionality

### Qualitative Metrics
- **Security Posture:** Demonstrable improvement in threat detection capability
- **Code Quality:** Clean, maintainable, well-documented code
- **User Experience:** No degradation in tool usability or output clarity
- **Maintainability:** Modular, extensible architecture for future enhancements

## Documentation Requirements

### Code Documentation
- [ ] Comprehensive inline documentation for all new functions
- [ ] Security rationale documented for each enhancement
- [ ] Performance characteristics documented for new algorithms
- [ ] Error handling and recovery procedures documented

### User Documentation  
- [ ] Updated CLI help with new security features
- [ ] Security monitoring guide updated with new patterns
- [ ] Troubleshooting guide updated with new error conditions
- [ ] Performance tuning guide updated with new optimization options

### Developer Documentation
- [ ] Architecture decision records for major design choices
- [ ] Testing strategy documentation updated
- [ ] Security testing procedures documented
- [ ] Future enhancement roadmap updated

---

**Note:** This task represents a significant security enhancement to bee-trace. The implementation should be done carefully with extensive testing at each phase. Consider running this task in a development environment first and gradually rolling out to production systems after thorough validation.