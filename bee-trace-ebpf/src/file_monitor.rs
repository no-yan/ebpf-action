use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
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
    // Get the filename pointer from the tracepoint arguments
    let Ok((path_buf, path_len)) = get_path_ptr(&ctx) else {
        return Err(0);
    };

    if !is_sensitive_file(path_buf, path_len) {
        return Ok(0);
    };

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: bee_trace_common::AccessType::File,
        path_len,
        path_or_var: path_buf,
    };

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
    Ok(0)
}

#[inline]
fn get_path_ptr(ctx: &TracePointContext) -> Result<([u8; 128], usize), i64> {
    let ptr = unsafe { ctx.read_at::<*const u8>(24)? };

    if ptr.is_null() {
        return Err(0);
    };

    // Read the filename from user space
    let mut path_buf = [0u8; 128];

    let path_len = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut path_buf) }
        .map_err(|_| 1i64)?
        .len();

    Ok((path_buf, path_len))
}

fn is_sensitive_file(path_buf: [u8; 128], path_len: usize) -> bool {
    let basename_idx = get_basename_start_index(path_buf);
    if basename_idx >= path_len {
        return false;
    }

    let basename_buf = &path_buf[basename_idx..path_len];
    if basename_buf.starts_with(b"credentials.json")
        || basename_buf.starts_with(b"id_rsa")
        || basename_buf.starts_with(b"id_dsa")
        || basename_buf.starts_with(b"id_ecdsa")
        || basename_buf.starts_with(b"id_ed25519")
        || basename_buf.starts_with(b".env")
        || basename_buf.starts_with(b"config.json")
        || basename_buf.starts_with(b"secrets.yaml")
        || basename_buf.starts_with(b"secrets.yml")
        || basename_buf.starts_with(b"private.key")
    {
        return true;
    }

    if basename_buf.len() < 4 {
        return false;
    }

    let start = basename_buf.len() - 4;
    let ext = &basename_buf[start..start + 4];
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

/// Given a file path, returns the index where the basename(file name) starts.
/// Typically, this type of function returns a slice, but this returns an index instead.
/// Returning an unsized array is expensive in eBPF verification and can exceed the instruction limit.
fn get_basename_start_index(path: [u8; 128]) -> usize {
    let len = path.len();
    if len == 0 {
        return 0;
    }

    let mut basename_start = 0;
    for i in (0..len).rev() {
        if path[i] == b'/' {
            basename_start = i + 1;
            break;
        }
    }
    basename_start
}
