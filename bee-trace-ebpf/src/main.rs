#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, socket_filter},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

#[map(name = "BLOCK_LIST")]
static mut BLOCK_LIST_MAP: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[map(name = "ALLOW_LIST")]
static mut ALLOW_LIST_MAP: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[socket_filter]
pub fn bee_trace(ctx: SkBuffContext) -> i64 {
    match unsafe { try_bee_trace(&ctx) } {
        Ok(pass) => pass as i64,
        Err(ret) => ret as i64,
    }
}

unsafe fn try_bee_trace(ctx: &SkBuffContext) -> Result<u32, u32> {
    let src = ctx.skb.remote_ipv4();
    let dst = ctx.skb.local_ipv4();

    if BLOCK_LIST_MAP.get(&src).is_some() || BLOCK_LIST_MAP.get(&dst).is_some() {
        info!(ctx, "blocked {:i} -> {:i}", src, dst);
        return Ok(0);
    }

    if ALLOW_LIST_MAP.get(&src).is_some() || ALLOW_LIST_MAP.get(&dst).is_some() {
        info!(ctx, "allowed {:i} -> {:i}", src, dst);
        return Ok(1);
    }

    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
