use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::{info, warn};
use bee_trace_common::SecretAccessEvent;
use core::str;
#[map]
static SECRET_ACCESS_EVENTS: PerfEventArray<SecretAccessEvent> = PerfEventArray::new(0);

#[map]
static WATCHED_PATTERNS: HashMap<[u8; 64], u8> = HashMap::with_max_entries(128, 0);

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_openat(ctx) }.unwrap_or(1)
}

#[inline]
unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    // Get the filename from the tracepoint arguments
    let filename_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;

    if filename_ptr.is_null() {
        return Ok(0);
    }

    // Read the filename from user space
    let mut filename_buf = [0u8; 128];

    let filename_len = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf)
        .map_err(|_| 1i64)?
        .len() as u32;

    // Check if the file matches any watched patterns
    if let Ok(filename) = str::from_utf8(&filename_buf[..filename_len.min(128) as usize]) {
        info!(&ctx, "monitoring file access: {}", filename);
    } else {
        warn!(&ctx, "failed to parse filename as UTF-8");
    }

    if !is_sensitive_file(&filename_buf, filename_len.try_into().unwrap()) {
        return Ok(0);
    }

    // Log when sensitive file is detected
    if let Ok(filename) = str::from_utf8(&filename_buf[..filename_len.min(128) as usize]) {
        info!(&ctx, "🚨 SENSITIVE FILE ACCESS DETECTED: {}", filename);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: bee_trace_common::AccessType::File,
        path_or_var: [0u8; 128],
        path_len: filename_len.min(128),
    };

    // Copy the filename to the event
    let copy_len = (filename_len as usize).min(event.path_or_var.len());
    event.path_or_var[..copy_len].copy_from_slice(&filename_buf[..copy_len]);

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
    Ok(0)
}

#[inline(never)]
unsafe fn is_sensitive_file(filename: &[u8; 128], len: usize) -> bool {
    if len == 0 || len > 128 {
        return false;
    }

    // Check for exact filename matches and path-based matches
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

    // Check if filename contains sensitive patterns (for absolute paths)
    let slice = &filename[..len];
    if contains_pattern(slice, b"id_rsa")
        || contains_pattern(slice, b"id_dsa")
        || contains_pattern(slice, b"id_ecdsa")
        || contains_pattern(slice, b"id_ed25519")
        || contains_pattern(slice, b"credentials.json")
        || contains_pattern(slice, b"private.key")
        || contains_pattern(slice, b"secrets.yaml")
        || contains_pattern(slice, b"secrets.yml")
        || contains_pattern(slice, b".env")
    {
        return true;
    }

    // Extension checks
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
            {
                return true;
            }
        }
    }

    false
}

#[inline(never)]
unsafe fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    let needle_len = needle.len();
    let haystack_len = haystack.len();

    for i in 0..=(haystack_len - needle_len) {
        let mut matches = true;
        for j in 0..needle_len {
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
