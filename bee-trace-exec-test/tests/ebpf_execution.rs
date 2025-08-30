use std::{fs::File, path::PathBuf, time::Duration};

use aya::{maps::PerfEventArray, util::online_cpus, Ebpf};
use bee_trace::ebpf_manager::{FileProbeManager, ProbeManager};
use bee_trace::errors::ProbeType;
use bee_trace_common::SecretAccessEvent;
use bytes::BytesMut;
use libc;

fn load_ebpf() -> anyhow::Result<Ebpf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let build_dir = manifest_dir
        .parent()
        .expect("workspace root")
        .join("target")
        .join(&profile)
        .join("build");
    for entry in std::fs::read_dir(build_dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("bee-trace-")
        {
            let candidate = entry
                .path()
                .join("out/bee-trace-ebpf/bpfel-unknown-none/release/bee-trace");
            if candidate.exists() {
                let data = std::fs::read(candidate)?;
                return Ok(Ebpf::load(&data)?);
            }
        }
    }
    Err(anyhow::anyhow!("eBPF object not found"))
}

#[test]
fn should_capture_secret_file_access_event() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping test, requires root privileges");
        return Ok(());
    }

    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut ebpf = load_ebpf()?;

    let mut manager = FileProbeManager::new();
    if let Err(e) = manager.attach(&mut ebpf, ProbeType::FileMonitor) {
        eprintln!("skipping test, failed to attach BPF program: {e}");
        return Ok(());
    }

    let mut perf_array: PerfEventArray<_> = ebpf
        .take_map("SECRET_ACCESS_EVENTS")
        .expect("map not found")
        .try_into()?;

    let mut buffers = Vec::new();
    for cpu in online_cpus().map_err(|e| anyhow::anyhow!("{:?}", e))? {
        buffers.push(perf_array.open(cpu, None)?);
    }

    let file_path = std::env::temp_dir().join(".env_test");
    std::fs::write(&file_path, b"KEY=VALUE")?;
    let _file = File::open(&file_path)?;

    std::thread::sleep(Duration::from_millis(100));

    let mut found = false;
    for buf in &mut buffers {
        let mut v = [BytesMut::with_capacity(1024)];
        if let Ok(events) = buf.read_events(&mut v) {
            for data in v.iter().take(events.read) {
                let event = unsafe { data.as_ptr().cast::<SecretAccessEvent>().read_unaligned() };
                if event.path_or_var_as_str().ends_with(".env_test") {
                    found = true;
                }
            }
        }
    }

    assert!(found, "no secret access event captured for .env_test file");
    Ok(())
}
