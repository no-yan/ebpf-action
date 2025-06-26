#![no_std]
#![no_main]

use aya_ebpf::{macros::socket_filter, programs::SkBuffContext};
pub use lsm::*;
mod lsm;

#[socket_filter]
pub fn bee_trace(_ctx: SkBuffContext) -> i64 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
