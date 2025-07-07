# Task 01: Minor Fixes & Quick Wins

**Priority:** HIGH  
**Estimated Time:** 2-4 hours  
**Complexity:** Low  
**Dependencies:** None  

## Overview

This task groups together small, easily fixable issues that can be completed quickly to improve code quality and fix immediate problems. These are standalone fixes that don't require architectural changes.

## Specific Fixes Required

### 1. Fix Typo in File Monitor Patterns

**File:** `bee-trace-ebpf/src/file_monitor.rs:86`  
**Issue:** Typo in sensitive file pattern  

```rust
// Current (line 86):
| filename.starts_with(b"secrerts.yaml")

// Should be:
| filename.starts_with(b"secrets.yaml")
```

### 2. Remove Dead Code in Network Module

**File:** `bee-trace-ebpf/src/network.rs:128-162`  
**Issue:** Commented out LSM hooks taking up space  

```rust
// Remove the entire commented block:
// LSM hooks can be problematic and require special kernel configuration
// Commenting out for compatibility
/*
#[lsm(hook = "socket_connect")]
pub fn socket_connect_hook(ctx: LsmContext) -> i32 {
    // ... entire commented section
}
*/
```

### 3. Fix Debug Code in File Monitor

**File:** `bee-trace-ebpf/src/file_monitor.rs:39-46`  
**Issue:** Inconsistent debug logging and commented code  

```rust
// Current:
// let filename_str = str::from_utf8(&filename_buf).expect("Invalid UTF-8");
// info!(&ctx, "filename: {}", filename_str);

if let Ok(filename) = str::from_utf8(&filename_buf) {
    info!(&ctx, "hi {}", filename);
} else {
    warn!(&ctx, "failed to parse filename");
}

// Should be (cleaner debug logging):
if let Ok(filename) = str::from_utf8(&filename_buf[..filename_len.min(128) as usize]) {
    info!(&ctx, "monitoring file access: {}", filename);
} else {
    warn!(&ctx, "failed to parse filename as UTF-8");
}
```

### 4. Add Missing File Extension Patterns

**File:** `bee-trace-ebpf/src/file_monitor.rs:94-109`  
**Issue:** Missing common sensitive file extensions  

```rust
// Add these extensions to the existing check:
if len >= 4 {
    let start = len - 4;
    if start < 124 {
        let ext = &filename[start..start + 4];
        if ext == b".pem"
            || ext == b".key"
            || ext == b".p12"
            || ext == b".pfx"
            || ext == b".crt"
            || ext == b".cer"
            || ext == b".der"
            || ext == b".p8k"  // Add this
            || ext == b".jks"  // Add this
        {
            return true;
        }
    }
}

// Also add 5-character extensions check:
if len >= 5 {
    let start = len - 5;
    if start < 123 {
        let ext = &filename[start..start + 5];
        if ext == b".pkcs" {
            return true;
        }
    }
}
```

### 5. Improve Error Context in Main

**File:** `bee-trace/src/main.rs:20-23`  
**Issue:** Generic error message without context  

```rust
// Current:
if let Err(e) = args.validate() {
    eprintln!("Error: {}", e);
    std::process::exit(1);
}

// Should be:
if let Err(e) = args.validate() {
    eprintln!("Configuration validation failed: {}", e);
    eprintln!("Use --help for usage information");
    std::process::exit(1);
}
```

## Implementation Steps

1. **Setup Development Environment**
   ```bash
   just setup
   cargo check
   ```

2. **Make Changes in Order**
   - Start with the typo fix (safest)
   - Remove dead code
   - Fix debug logging
   - Add file extensions
   - Improve error messages

3. **Test Each Change**
   ```bash
   cargo test
   cargo build --release
   just test-security
   ```

4. **Verify eBPF Compilation**
   ```bash
   cargo build -p bee-trace-ebpf
   ```

## Acceptance Criteria

- [ ] All typos fixed in file monitor patterns
- [ ] Dead code removed from network module
- [ ] Debug logging is consistent and informative
- [ ] New file extensions properly detected in tests
- [ ] Error messages provide helpful context
- [ ] All existing tests continue to pass
- [ ] eBPF programs compile successfully
- [ ] No new compiler warnings introduced

## Testing Strategy

### Unit Tests
```bash
# Test file pattern matching
cargo test -p bee-trace-common -- network_event
cargo test -p bee-trace-ebpf -- ebpf_program_structure

# Test error handling
cargo test --test integration_tests -- cli_argument_parsing
```

### Manual Testing
```bash
# Test file monitoring with new patterns
echo "test" > test.jks
just run-file-monitor --duration 5 --verbose

# Verify typo fix works
echo "test" > secrets.yaml
just run-file-monitor --duration 5
```

## Risk Assessment

**Risk Level:** LOW

- **Technical Risk:** Minimal - simple text changes
- **Breaking Changes:** None - purely additive or corrective
- **Performance Impact:** None - minor pattern additions only
- **Security Impact:** Positive - fixes security monitoring gaps

## Notes for Implementer

- This task is ideal for new contributors
- Can be completed in a single PR
- Good opportunity to familiarize with the codebase
- Changes are self-contained and easily reviewable

## Related Files

- `bee-trace-ebpf/src/file_monitor.rs` - Main fixes
- `bee-trace-ebpf/src/network.rs` - Dead code removal  
- `bee-trace/src/main.rs` - Error message improvement
- `bee-trace-common/src/lib.rs` - Test validation

## Success Metrics

- Zero new compiler warnings
- All existing tests continue passing
- File monitoring catches more sensitive files
- Debug output is more informative
- Error messages are more helpful