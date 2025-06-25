use aya_ebpf::{
    helpers::gen::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    },
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
};
use bee_trace_common::FileReadEvent;

use crate::vmlinux::file;

#[map]
static FILE_READ_EVENTS: PerfEventArray<FileReadEvent> = PerfEventArray::new(0);


#[kprobe]
pub fn vfs_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_read(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_vfs_read(ctx: ProbeContext) -> Result<u32, i64> {
    let file: *const file = ctx.arg::<*const file>(0).ok_or(1i64)?;
    let count: usize = ctx.arg::<usize>(2).ok_or(1i64)?;

    if file.is_null() {
        return Ok(0);
    }

    let mut event = FileReadEvent {
        pid: 0,
        uid: 0,
        filename: [0u8; 64],
        filename_len: 0,
        bytes_read: count as u64,
        comm: [0u8; 16],
    };

    // Get process info
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;

    // Get command name
    if bpf_get_current_comm(event.comm.as_mut_ptr() as *mut _, event.comm.len() as u32) < 0 {
        return Ok(0);
    }

    // For VFS kprobe, we can't safely access file paths due to verifier constraints
    // Use a placeholder to indicate VFS read events
    let placeholder = b"<vfs>";
    let copy_len = if placeholder.len() > event.filename.len() {
        event.filename.len()
    } else {
        placeholder.len()
    };
    
    for i in 0..copy_len {
        event.filename[i] = placeholder[i];
    }
    event.filename_len = copy_len as u32;

    FILE_READ_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_read(ctx) } {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

unsafe fn try_sys_enter_read(ctx: TracePointContext) -> Result<u32, i64> {
    let fd: i32 = ctx.read_at::<i32>(16)?;
    let count: usize = ctx.read_at::<usize>(24)?;

    if fd < 0 {
        return Ok(0);
    }

    let mut event = FileReadEvent {
        pid: 0,
        uid: 0,
        filename: [0u8; 64],
        filename_len: 0,
        bytes_read: count as u64,
        comm: [0u8; 16],
    };

    // Get process info
    let pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    event.uid = uid_gid as u32;

    // Get command name
    if bpf_get_current_comm(event.comm.as_mut_ptr() as *mut _, event.comm.len() as u32) < 0 {
        return Ok(0);
    }

    // For syscall tracing, we can't easily get the filename, so we'll use a placeholder
    let placeholder = b"<fd>";
    for (i, &byte) in placeholder.iter().enumerate() {
        if i < event.filename.len() {
            event.filename[i] = byte;
        }
    }
    event.filename_len = placeholder.len() as u32;

    FILE_READ_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}
