# Task 02: Network Monitoring IP Address Enhancement

**Priority:** HIGH  
**Estimated Time:** 6-8 hours  
**Complexity:** Medium  
**Dependencies:** None  

## Overview

Currently, the network monitoring displays placeholder text (`<ipv4>` and `<ipv6>`) instead of actual IP addresses. This task implements proper IPv4 and IPv6 address formatting for the `NetworkEvent` structure, enabling better security monitoring and debugging capabilities.

## Current Problem

**File:** `bee-trace-common/src/lib.rs:138-147`

```rust
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
```

## Proposed Solution

### 1. Add IP Address Formatting Module

**New File:** `bee-trace-common/src/ip_formatting.rs`

```rust
#![no_std]

use core::fmt::Write;

/// Format IPv4 address from 4-byte array to string
/// Returns formatted string like "192.168.1.1"
pub fn format_ipv4(ip_bytes: &[u8; 4]) -> heapless::String<15> {
    let mut result = heapless::String::new();
    write!(
        result,
        "{}.{}.{}.{}",
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
    )
    .unwrap_or(());
    result
}

/// Format IPv6 address from 16-byte array to string
/// Returns compressed format like "2001:db8::1"
pub fn format_ipv6(ip_bytes: &[u8; 16]) -> heapless::String<45> {
    let mut result = heapless::String::new();
    
    // Convert bytes to u16 groups
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([ip_bytes[i * 2], ip_bytes[i * 2 + 1]]);
    }
    
    // Find longest sequence of zeros for compression
    let (zero_start, zero_len) = find_longest_zero_sequence(&groups);
    
    // Format with compression
    format_ipv6_with_compression(&mut result, &groups, zero_start, zero_len);
    
    result
}

fn find_longest_zero_sequence(groups: &[u16; 8]) -> (usize, usize) {
    let mut max_start = 0;
    let mut max_len = 0;
    let mut current_start = 0;
    let mut current_len = 0;
    
    for (i, &group) in groups.iter().enumerate() {
        if group == 0 {
            if current_len == 0 {
                current_start = i;
            }
            current_len += 1;
        } else {
            if current_len > max_len && current_len > 1 {
                max_start = current_start;
                max_len = current_len;
            }
            current_len = 0;
        }
    }
    
    // Check final sequence
    if current_len > max_len && current_len > 1 {
        max_start = current_start;
        max_len = current_len;
    }
    
    (max_start, max_len)
}

fn format_ipv6_with_compression(
    result: &mut heapless::String<45>,
    groups: &[u16; 8],
    zero_start: usize,
    zero_len: usize,
) {
    let use_compression = zero_len > 1;
    
    for i in 0..8 {
        if use_compression && i == zero_start {
            if i == 0 {
                write!(result, "::").unwrap_or(());
            } else {
                write!(result, ":").unwrap_or(());
            }
            // Skip zero groups
            let skip_to = zero_start + zero_len;
            if skip_to == 8 {
                return; // Address ends with compressed zeros
            }
            continue;
        }
        
        if use_compression && i > zero_start && i < zero_start + zero_len {
            continue; // Skip zeros in compressed section
        }
        
        if i > 0 && !(use_compression && i == zero_start + zero_len) {
            write!(result, ":").unwrap_or(());
        }
        
        write!(result, "{:x}", groups[i]).unwrap_or(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_format_ipv4_address() {
        let ip = [192, 168, 1, 1];
        let formatted = format_ipv4(&ip);
        assert_eq!(formatted.as_str(), "192.168.1.1");
    }

    #[test]
    fn should_format_ipv6_address_without_compression() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let formatted = format_ipv6(&ip);
        assert_eq!(formatted.as_str(), "2001:db8::1");
    }

    #[test]
    fn should_format_ipv6_localhost() {
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let formatted = format_ipv6(&ip);
        assert_eq!(formatted.as_str(), "::1");
    }
}
```

### 2. Update NetworkEvent Implementation

**File:** `bee-trace-common/src/lib.rs`

```rust
// Add to dependencies in Cargo.toml
// heapless = "0.8"

// Update the lib.rs file
mod ip_formatting;

use ip_formatting::{format_ipv4, format_ipv6};

impl NetworkEvent {
    /// Get destination IP address as formatted string
    /// For IPv4: returns "192.168.1.1" format
    /// For IPv6: returns compressed format like "2001:db8::1"
    pub fn dest_ip_as_string(&self) -> heapless::String<45> {
        if self.is_ipv6 == 0 {
            // IPv4 - take first 4 bytes
            let ipv4_bytes = [
                self.dest_ip[0],
                self.dest_ip[1], 
                self.dest_ip[2],
                self.dest_ip[3]
            ];
            let ipv4_str = format_ipv4(&ipv4_bytes);
            let mut result = heapless::String::new();
            result.push_str(&ipv4_str).unwrap_or(());
            result
        } else {
            // IPv6 - use all 16 bytes
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes.copy_from_slice(&self.dest_ip);
            format_ipv6(&ipv6_bytes)
        }
    }

    /// Legacy method for backward compatibility
    /// Returns static string for performance in eBPF context
    pub fn dest_ip_as_str(&self) -> &str {
        if self.is_ipv6 == 0 {
            "<ipv4>"
        } else {
            "<ipv6>"
        }
    }
}
```

### 3. Update Display Formatter

**File:** `bee-trace/src/lib.rs` - EventFormatter implementation

```rust
impl EventFormatter for TableFormatter {
    fn format_event(&self, event: &SecurityEvent) -> String {
        match event {
            SecurityEvent::Network(net_event) => {
                let ip_display = net_event.dest_ip_as_string();
                format!(
                    "{:<8} {:<8} {:<16} {:<15} {:<6} {:<8} {:<8}",
                    net_event.pid(),
                    if self.show_uid { net_event.uid().to_string() } else { String::new() },
                    net_event.command_as_str(),
                    ip_display.as_str(),  // Use actual IP instead of placeholder
                    net_event.dest_port,
                    net_event.protocol_as_str(),
                    net_event.action_as_str()
                )
            }
            // ... other event types
        }
    }
}
```

## Implementation Steps

### Phase 1: Add IP Formatting Module (2-3 hours)
1. Create `bee-trace-common/src/ip_formatting.rs`
2. Add heapless dependency to `bee-trace-common/Cargo.toml`
3. Implement IPv4 formatting with tests
4. Implement IPv6 formatting with compression
5. Add comprehensive test coverage

### Phase 2: Update NetworkEvent (2-3 hours)
1. Update `bee-trace-common/src/lib.rs` to include new module
2. Add `dest_ip_as_string()` method
3. Keep `dest_ip_as_str()` for backward compatibility
4. Add tests for both IPv4 and IPv6 scenarios

### Phase 3: Update Formatters (1-2 hours)
1. Update `TableFormatter` to use real IP addresses
2. Update any other formatters that display network events
3. Test display output manually

### Phase 4: Testing & Validation (1-2 hours)
1. Add unit tests for all IP formatting scenarios
2. Test with real network events
3. Verify performance impact is minimal
4. Update integration tests if needed

## Dependencies Required

Add to `bee-trace-common/Cargo.toml`:
```toml
[dependencies]
heapless = "0.8"
```

## Acceptance Criteria

- [ ] IPv4 addresses display as "192.168.1.1" format
- [ ] IPv6 addresses display in compressed format (e.g., "2001:db8::1")
- [ ] Special IPv6 addresses handled correctly (::1, ::, etc.)
- [ ] Backward compatibility maintained (`dest_ip_as_str()` still works)
- [ ] No allocation in no_std context (uses heapless)
- [ ] Comprehensive test coverage for all IP formats
- [ ] Performance impact < 5% for network event processing
- [ ] Manual testing shows real IP addresses in output

## Test Cases

### IPv4 Test Cases
```rust
#[test]
fn test_common_ipv4_addresses() {
    assert_eq!(format_ipv4(&[127, 0, 0, 1]), "127.0.0.1");
    assert_eq!(format_ipv4(&[192, 168, 1, 1]), "192.168.1.1");
    assert_eq!(format_ipv4(&[10, 0, 0, 1]), "10.0.0.1");
    assert_eq!(format_ipv4(&[172, 16, 0, 1]), "172.16.0.1");
}
```

### IPv6 Test Cases
```rust
#[test]
fn test_ipv6_compression() {
    // Localhost
    let localhost = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(format_ipv6(&localhost), "::1");
    
    // Documentation prefix
    let doc_prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(format_ipv6(&doc_prefix), "2001:db8::1");
}
```

## Performance Considerations

- Use `heapless::String` to avoid allocations
- Keep IPv4 formatting simple (no complex parsing)
- IPv6 compression algorithm is O(n) where n=8 (constant time)
- Caching could be added later if needed
- eBPF context continues using placeholder strings for performance

## Risk Assessment

**Risk Level:** MEDIUM

- **Technical Risk:** Medium - String formatting in no_std context
- **Breaking Changes:** None - adds new method, keeps old one
- **Performance Impact:** Low - only affects display formatting
- **Security Impact:** Positive - better visibility of network connections

## Manual Testing

```bash
# Test with real network activity
just run-network-monitor --duration 30 --verbose

# Test with specific network commands
ping 8.8.8.8 &  # Should show IPv4
ping6 google.com &  # Should show IPv6 (if available)

# Verify in output
just run-network-monitor --duration 10 | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-f]*:){2,7}[0-9a-f]*"
```

## Related Tasks

- Can be developed in parallel with other tasks
- Provides foundation for future network security enhancements  
- Enables better debugging and monitoring capabilities

## Success Metrics

- Real IP addresses visible in network monitoring output
- No performance regression in network event processing
- All existing tests continue to pass
- New IP formatting tests achieve 100% coverage