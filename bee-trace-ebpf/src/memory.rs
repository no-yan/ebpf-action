use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};
use bee_trace_common::{ProcessMemoryEvent, SecretAccessEvent};

#[map]
static PROCESS_MEMORY_EVENTS: PerfEventArray<ProcessMemoryEvent> = PerfEventArray::new(0);

#[map]
static ENV_ACCESS_EVENTS: PerfEventArray<SecretAccessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_ptrace(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_enter_ptrace(ctx: TracePointContext) -> Result<u32, i64> {
    let _request: i64 = ctx.read_at::<i64>(16)?;
    let target_pid: u32 = ctx.read_at::<u32>(24)?;

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let event = ProcessMemoryEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        target_pid,
        target_comm: [0u8; 16], // Would need to resolve target process name
        syscall_type: 0,        // ptrace
    };

    PROCESS_MEMORY_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_process_vm_readv(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_process_vm_readv(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_enter_process_vm_readv(ctx: TracePointContext) -> Result<u32, i64> {
    let target_pid: u32 = ctx.read_at::<u32>(16)?;

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let event = ProcessMemoryEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        target_pid,
        target_comm: [0u8; 16],
        syscall_type: 1, // process_vm_readv
    };

    PROCESS_MEMORY_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// Note: uprobe for getenv would need to be attached to specific binaries
// Commenting out uprobe as it requires specific binary attachment and can cause verifier issues
/*
#[uprobe]
pub fn getenv(ctx: ProbeContext) -> u32 {
    match unsafe { try_getenv(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_getenv(ctx: ProbeContext) -> Result<u32, i64> {
    let name_ptr: *const u8 = ctx.arg::<*const u8>(0).ok_or(1i64)?;

    if name_ptr.is_null() {
        return Ok(0);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let mut var_name_buf = [0u8; 128];
    let name_len = bpf_probe_read_user_str_bytes(name_ptr, &mut var_name_buf)
        .map_err(|_| 1i64)?
        .len() as u32;

    // Check if this is a sensitive environment variable
    if !is_sensitive_env_var(&var_name_buf, name_len) {
        return Ok(0);
    }

    let mut event = SecretAccessEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        access_type: 1, // Environment variable access
        path_or_var: [0u8; 128],
        path_len: name_len.min(128),
    };

    // Copy the variable name to the event
    let copy_len = (name_len as usize).min(event.path_or_var.len());
    for i in 0..copy_len {
        event.path_or_var[i] = var_name_buf[i];
    }

    ENV_ACCESS_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}
*/

unsafe fn is_sensitive_env_var(var_name: &[u8; 128], len: u32) -> bool {
    // Check for common sensitive environment variable patterns
    if len >= 7 && starts_with_pattern(&var_name[..len as usize], b"SECRET_") {
        return true;
    }
    if len >= 8 && starts_with_pattern(&var_name[..len as usize], b"PASSWORD") {
        return true;
    }
    if len >= 6 && starts_with_pattern(&var_name[..len as usize], b"PASSWD") {
        return true;
    }
    if len >= 5 && starts_with_pattern(&var_name[..len as usize], b"TOKEN") {
        return true;
    }
    if len >= 3 && starts_with_pattern(&var_name[..len as usize], b"KEY") {
        return true;
    }
    if len >= 7 && starts_with_pattern(&var_name[..len as usize], b"API_KEY") {
        return true;
    }

    false
}

unsafe fn starts_with_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    for i in 0..needle.len() {
        if haystack[i] != needle[i] {
            return false;
        }
    }
    true
}
