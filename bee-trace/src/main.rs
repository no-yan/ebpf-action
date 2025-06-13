use aya::{maps::HashMap as AyaHashMap, programs::SocketFilter};
#[rustfmt::skip]
use log::{debug, warn};
use std::{net::{Ipv4Addr, SocketAddr}, str::FromStr};
use bee_trace_common::{ALLOW_LIST, BLOCK_LIST};
use tokio::{net::lookup_host, signal};
use anyhow::anyhow;

async fn parse_address_list(list: &str) -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    for item in list.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Ok(ip) = Ipv4Addr::from_str(item) {
            addrs.push(ip);
            continue;
        }
        if let Ok(resolved) = lookup_host((item, 0)).await {
            for addr in resolved {
                if let SocketAddr::V4(v4) = addr {
                    addrs.push(*v4.ip());
                }
            }
        }
    }
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_ip() {
        let res = parse_address_list("127.0.0.1").await;
        assert_eq!(res, vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }

    #[tokio::test]
    async fn parse_domain() {
        let res = parse_address_list("localhost").await;
        assert!(res.contains(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[tokio::test]
    async fn parse_multiple() {
        let res = parse_address_list("127.0.0.1,localhost").await;
        assert!(res.contains(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(res.len() >= 1);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bee-trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let mut block_map = AyaHashMap::<_, u32, u8>::try_from(
        ebpf.take_map(BLOCK_LIST).ok_or_else(|| anyhow!("map not found"))?,
    )?;
    let mut allow_map = AyaHashMap::<_, u32, u8>::try_from(
        ebpf.take_map(ALLOW_LIST).ok_or_else(|| anyhow!("map not found"))?,
    )?;

    if let Ok(list) = std::env::var("BLOCK_LIST") {
        for addr in parse_address_list(&list).await {
            let _ = block_map.insert(u32::from(addr), 1, 0);
        }
    }

    if let Ok(list) = std::env::var("ALLOW_LIST") {
        for addr in parse_address_list(&list).await {
            let _ = allow_map.insert(u32::from(addr), 1, 0);
        }
    }
    let listener = std::net::TcpListener::bind("localhost:0")?;
    let prog: &mut SocketFilter = ebpf.program_mut("bee_trace").unwrap().try_into()?;
    prog.load()?;
    prog.attach(&listener)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
