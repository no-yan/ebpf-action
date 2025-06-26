use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use bee_trace_common::SecretAccessEvent;

#[map]
static SECRET_ACCESS_EVENTS: PerfEventArray<SecretAccessEvent> = PerfEventArray::new(0);

#[map]
static WATCHED_PATTERNS: HashMap<[u8; 64], u8> = HashMap::with_max_entries(128, 0);

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_openat(ctx) }.unwrap_or(1)
}

unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    // Get the filename from the tracepoint arguments
    let filename_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;

    if filename_ptr.is_null() {
        return Ok(0);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    // Read the filename from user space
    let mut filename_buf = [0u8; 128];
    let filename_len = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf)
        .map_err(|_| 1i64)?
        .len() as u32;

    // Check if the file matches any watched patterns
    if !is_sensitive_file(&filename_buf, filename_len) {
        return Ok(0);
    }

    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: 0, // File access
        path_or_var: [0u8; 128],
        path_len: filename_len.min(128),
    };

    // Copy the filename to the event
    let copy_len = (filename_len as usize).min(event.path_or_var.len());
    event.path_or_var[..copy_len].copy_from_slice(&filename_buf[..copy_len]);

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

unsafe fn is_sensitive_file(filename: &[u8; 128], len: u32) -> bool {
    let filename_slice = &filename[..len.min(128) as usize];

    // Check for common sensitive file patterns
    if contains_pattern(filename_slice, b"credentials.json") {
        return true;
    }
    if contains_pattern(filename_slice, b"id_rsa") {
        return true;
    }
    if contains_pattern(filename_slice, b"id_dsa") {
        return true;
    }
    if contains_pattern(filename_slice, b"id_ecdsa") {
        return true;
    }
    if contains_pattern(filename_slice, b"id_ed25519") {
        return true;
    }
    if contains_pattern(filename_slice, b".env") {
        return true;
    }
    if contains_pattern(filename_slice, b"config.json") {
        return true;
    }
    if contains_pattern(filename_slice, b"secrets.yaml") {
        return true;
    }
    if contains_pattern(filename_slice, b"secrets.yml") {
        return true;
    }
    if contains_pattern(filename_slice, b"private.key") {
        return true;
    }

    // Check for files ending with common sensitive extensions
    if ends_with(filename_slice, b".pem") {
        return true;
    }
    if ends_with(filename_slice, b".key") {
        return true;
    }
    if ends_with(filename_slice, b".p12") {
        return true;
    }
    if ends_with(filename_slice, b".pfx") {
        return true;
    }
    if ends_with(filename_slice, b".crt") {
        return true;
    }
    if ends_with(filename_slice, b".cer") {
        return true;
    }
    if ends_with(filename_slice, b".der") {
        return true;
    }

    false
}

unsafe fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        let mut matches = true;
        for j in 0..needle.len() {
            if haystack[i + j] != needle[j] {
                matches = false;
                break;
            }
        }
        if matches {
            return true;
        }
    }
    false
}

unsafe fn ends_with(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    let start = haystack.len() - needle.len();
    for i in 0..needle.len() {
        if haystack[start + i] != needle[i] {
            return false;
        }
    }
    true
}
