use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
    EbpfContext,
};
use bee_trace_bindings::{sock, sock_common};
use bee_trace_common::NetworkEvent;

#[map]
static NETWORK_EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

#[map]
static BLOCKED_IPS: aya_ebpf::maps::HashMap<u32, u8> =
    aya_ebpf::maps::HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_connect(ctx) }.unwrap_or(1)
}

unsafe fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *const sock = ctx.arg::<*const sock>(0).ok_or(1i64)?;
    if sock.is_null() {
        return Ok(0);
    }

    let sk_common: sock_common = bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)?;

    let family = sk_common.skc_family;
    let mut event = NetworkEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm: ctx.command().unwrap_or_default(),
        dest_ip: [0u8; 16],
        dest_port: sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport
            .to_be(),
        protocol: 0, // TCP
        is_ipv6: if family == 10 { 1 } else { 0 },
        action: 0,
    };

    if family == 2 {
        // IPv4
        let dest_ip = sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_daddr
            .to_be_bytes();
        event.dest_ip[0..4].copy_from_slice(&dest_ip);
        if BLOCKED_IPS
            .get(&sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr)
            .is_some()
        {
            event.action = 1;
        }
    } else if family == 10 {
        // IPv6
        let dest_ip = sk_common.skc_v6_daddr.in6_u.u6_addr8;
        event.dest_ip.copy_from_slice(&dest_ip);
    }

    NETWORK_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) -> u32 {
    unsafe { try_udp_sendmsg(ctx) }.unwrap_or(1)
}

unsafe fn try_udp_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *const sock = ctx.arg::<*const sock>(0).ok_or(1i64)?;
    if sock.is_null() {
        return Ok(0);
    }

    let sk_common: sock_common = bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)?;

    let family = sk_common.skc_family;
    let mut event = NetworkEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm: ctx.command().unwrap_or_default(),
        dest_ip: [0u8; 16],
        dest_port: sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport
            .to_be(),
        protocol: 1, // UDP
        is_ipv6: if family == 10 { 1 } else { 0 },
        action: 0,
    };

    if family == 2 {
        // IPv4
        let dest_ip = sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_daddr
            .to_be_bytes();
        event.dest_ip[0..4].copy_from_slice(&dest_ip);
        if BLOCKED_IPS
            .get(&sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr)
            .is_some()
        {
            event.action = 1;
        }
    } else if family == 10 {
        // IPv6
        let dest_ip = sk_common.skc_v6_daddr.in6_u.u6_addr8;
        event.dest_ip.copy_from_slice(&dest_ip);
    }

    NETWORK_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// LSM hooks can be problematic and require special kernel configuration
// Commenting out for compatibility
/*
#[lsm(hook = "socket_connect")]
pub fn socket_connect_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_socket_connect(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0, // Allow by default on error
    }
}

unsafe fn try_socket_connect(ctx: LsmContext) -> Result<i32, i64> {
    let Ok(comm) = ctx.command() else {
        return Ok(0);
    };

    // This is where we would implement the actual IP blocking logic
    // For now, we'll just log the connection attempt
    let event = NetworkEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        comm,
        dest_ip: [0u8; 16], // Would extract from socket address
        dest_port: 0,       // Would extract from socket address
        protocol: 0,        // Would determine from socket type
        is_ipv6: 0,
        action: 0, // Would be determined based on blocklist
    };

    NETWORK_EVENTS.output(&ctx, &event, 0);

    // Return 0 to allow, -EPERM (-1) to block
    Ok(0)
}
*/
