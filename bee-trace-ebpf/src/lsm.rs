use aya_ebpf::{
    macros::{kprobe, map, tracepoint},
    maps::PerfEventArray,
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use bee_trace_bindings::file;
use bee_trace_common::FileReadEvent;

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

    if file.is_null() {
        return Ok(0);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };
    let mut event = FileReadEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        filename: [0u8; 64],
        filename_len: 0,
        comm,
    };

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

    if fd < 0 {
        return Ok(0);
    }

    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    let mut event = FileReadEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        filename: [0u8; 64],
        filename_len: 0,
        comm,
    };

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
