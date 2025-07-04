use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use bee_trace_common::SecretAccessEvent;
use core::str::{self};

#[map]
static SECRET_ACCESS_EVENTS: PerfEventArray<SecretAccessEvent> = PerfEventArray::new(0);

#[map]
static WATCHED_PATTERNS: HashMap<[u8; 64], u8> = HashMap::with_max_entries(128, 0);

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_openat(ctx) }.unwrap_or(1)
}

#[inline(never)]
unsafe fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    // Get the filename from the tracepoint arguments

    let Ok(_val @ true) = is_sensitive_file(&ctx) else {
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
        path_len: 128,
        path_or_var: [0u8; 128],
    };

    // event.path_or_var[..copy_len].copy_from_slice(&path_buf[..copy_len]);

    SECRET_ACCESS_EVENTS.output(&ctx, &event, 0);
    info!(&ctx, "🔔 Event sent to userspace for PID: {}", ctx.pid());
    Ok(0)
}

#[inline]
fn get_path_ptr(ctx: &TracePointContext) -> Result<*const u8, i64> {
    let ptr = unsafe { ctx.read_at::<*const u8>(24)? };

    if ptr.is_null() {
        Err(0)
    } else {
        Ok(ptr)
    }
}

#[inline(never)]
fn is_sensitive_file(ctx: &TracePointContext) -> Result<bool, i64> {
    let Ok(ptr) = get_path_ptr(&ctx) else {
        return Err(0);
    };

    // Read the filename from user space
    let mut path_buf = [0u8; 128];
    let path_len = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut path_buf) }
        .map_err(|_| 1i64)?
        .len();

    let basename_indx = get_basename_start_index(path_buf);
    if basename_indx >= path_len {
        return Err(0);
    }

    let basename_buf = &path_buf[basename_indx..path_len];
    let basename_str = unsafe { str::from_utf8_unchecked(basename_buf) };
    if basename_str.starts_with("credentials.json")
        || basename_str.starts_with("id_rsa")
        || basename_str.starts_with("id_dsa")
        || basename_str.starts_with("id_ecdsa")
        || basename_str.starts_with("id_ed25519")
        || basename_str.starts_with(".env")
        || basename_str.starts_with("config.json")
        || basename_str.starts_with("secrets.yaml")
        || basename_str.starts_with("secrets.yml")
        || basename_str.starts_with("private.key")
    {
        return Ok(true);
    }

    if basename_buf.len() < 4 {
        return Ok(false);
    }

    let start = basename_str.len() - 4;
    let ext = &basename_buf[start..start + 4];
    if ext == b".pem"
        || ext == b".key"
        || ext == b".p12"
        || ext == b".pfx"
        || ext == b".crt"
        || ext == b".cer"
        || ext == b".der"
    {
        return Ok(true);
    }

    Ok(false)
}

#[inline(never)]
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
