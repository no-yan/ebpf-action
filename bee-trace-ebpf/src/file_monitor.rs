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

#[inline]
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
    if !is_sensitive_file(&filename_buf, filename_len.try_into().unwrap()) {
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

#[inline(never)]
unsafe fn is_sensitive_file(filename: &[u8; 128], len: usize) -> bool {
    if len == 0 || len > 128 {
        return false;
    }

    if filename.starts_with(b"credentials.json")
        | filename.starts_with(b"id_rsa")
        | filename.starts_with(b"id_dsa")
        | filename.starts_with(b"id_ecdsa")
        | filename.starts_with(b"id_ed25519")
        | filename.starts_with(b".env")
        | filename.starts_with(b"config.json")
        | filename.starts_with(b"secrerts.yaml")
        | filename.starts_with(b"secrets.yml")
        | filename.starts_with(b"private.key")
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
