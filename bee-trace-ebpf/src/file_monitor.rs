use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use bee_trace_common::SecretAccessEvent;
use core::str;

macro_rules! basename {
    ($path: expr) => {{
        let path = $path.as_bytes();
        let mut basename_start_idx = 0;
        for i in (0..path.len()).rev() {
            if path[i] == b'/' {
                basename_start_idx = i + 1;
                break;
            }
        }

        &path[basename_start_idx..path.len()]
    }};
}

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
    let path_ptr: *const u8 = ctx.read_at::<*const u8>(24)?;

    if path_ptr.is_null() {
        return Ok(0);
    }

    // Read the filename from user space
    let mut path_buf = [0u8; 128];
    let path_len = bpf_probe_read_user_str_bytes(path_ptr, &mut path_buf)
        .map_err(|_| 1i64)?
        .len() as u32;

    // Check if the file matches any watched patterns
    let filename = str::from_utf8_unchecked(&path_buf[..path_len as usize]);
    info!(&ctx, "monitoring file access: {}", filename);

    if !is_sensitive_file(&path_buf) {
        return Ok(0);
    }

    let basename_str = str::from_utf8_unchecked(&basename!(filename));
    info!(&ctx, "basename test: {}", basename_str);
    // Log when sensitive file is detected

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: bee_trace_common::AccessType::File,
        path_or_var: [0u8; 128],
        path_len: path_len.min(128),
    };

    // Copy the filename to the event
    let copy_len = (path_len as usize).min(event.path_or_var.len());
    event.path_or_var[..copy_len].copy_from_slice(&path_buf[..copy_len]);

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
    Ok(0)
}

#[inline(never)]
unsafe fn is_sensitive_file(filename: &[u8]) -> bool {
    //
    // let basename = &filename[basename_start_idx..filename.len()];
    // let basename_str = str::from_utf8_unchecked(basename);
    // if basename_str.starts_with("credentials.json")
    //     || basename_str.starts_with("id_rsa")
    //     || basename_str.starts_with("id_dsa")
    //     || basename_str.starts_with("id_ecdsa")
    //     || basename_str.starts_with("id_ed25519")
    //     || basename_str.starts_with(".env")
    //     || basename_str.starts_with("config.json")
    //     || basename_str.starts_with("secrets.yaml")
    //     || basename_str.starts_with("secrets.yml")
    //     || basename_str.starts_with("private.key")
    // {
    //     return true;
    // }

    if filename.len() < 4 {
        return false;
    }

    let start = filename.len() - 4;
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

    false
}
