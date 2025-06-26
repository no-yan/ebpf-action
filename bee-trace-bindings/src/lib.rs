#![no_std]

#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[warn(unknown_lints)]
#[allow(unnecessary_transmutes)]
#[rustfmt::skip]
pub mod vmlinux;

pub use vmlinux::*;
