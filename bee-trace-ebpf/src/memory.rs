use aya_ebpf::{
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

// Note: Environment variable monitoring functions have been removed
// as they are not currently used by the active tracepoints.
// They were part of a uprobe implementation that requires specific
// binary attachment and can cause verifier issues.
