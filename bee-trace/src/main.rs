use std::time::Duration;

use aya::{
    maps::PerfEventArray,
    programs::{KProbe, TracePoint},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bee_trace::{Args, EventFormatter};
use bee_trace_common::{FileReadEvent, NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use tokio::{signal, time::timeout};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

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

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bee-trace"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Attach the appropriate probe(s) based on user selection
    match args.probe_type.as_str() {
        "vfs_read" => {
            let program: &mut KProbe = ebpf.program_mut("vfs_read").unwrap().try_into()?;
            program.load()?;
            program.attach("vfs_read", 0)?;
            info!("Attached kprobe to vfs_read");
        }
        "sys_enter_read" => {
            let program: &mut TracePoint =
                ebpf.program_mut("sys_enter_read").unwrap().try_into()?;
            program.load()?;
            program.attach("syscalls", "sys_enter_read")?;
            info!("Attached tracepoint to sys_enter_read");
        }
        "file_monitor" => {
            let program: &mut TracePoint =
                ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
            program.load()?;
            program.attach("syscalls", "sys_enter_openat")?;
            info!("Attached tracepoint to sys_enter_openat for file monitoring");
        }
        "network_monitor" => {
            // Attach TCP connection monitoring
            let tcp_program: &mut KProbe = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
            tcp_program.load()?;
            tcp_program.attach("tcp_connect", 0)?;
            info!("Attached kprobe to tcp_connect");

            // Attach UDP monitoring
            let udp_program: &mut KProbe = ebpf.program_mut("udp_sendmsg").unwrap().try_into()?;
            udp_program.load()?;
            udp_program.attach("udp_sendmsg", 0)?;
            info!("Attached kprobe to udp_sendmsg");

            // Note: LSM programs require special setup and are complex to attach properly
            // For now, we'll skip LSM and focus on kprobes/tracepoints
            info!("Network monitoring active (LSM socket_connect hook skipped for compatibility)");
        }
        "memory_monitor" => {
            // Attach ptrace monitoring
            let ptrace_program: &mut TracePoint =
                ebpf.program_mut("sys_enter_ptrace").unwrap().try_into()?;
            ptrace_program.load()?;
            ptrace_program.attach("syscalls", "sys_enter_ptrace")?;
            info!("Attached tracepoint to sys_enter_ptrace");

            // Attach process_vm_readv monitoring
            let vm_program: &mut TracePoint = ebpf
                .program_mut("sys_enter_process_vm_readv")
                .unwrap()
                .try_into()?;
            vm_program.load()?;
            vm_program.attach("syscalls", "sys_enter_process_vm_readv")?;
            info!("Attached tracepoint to sys_enter_process_vm_readv");
        }
        "all" => {
            // Attach all monitoring programs
            // File monitoring
            let file_program: &mut TracePoint =
                ebpf.program_mut("sys_enter_openat").unwrap().try_into()?;
            file_program.load()?;
            file_program.attach("syscalls", "sys_enter_openat")?;
            info!("Attached tracepoint to sys_enter_openat");

            // Network monitoring
            let tcp_program: &mut KProbe = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
            tcp_program.load()?;
            tcp_program.attach("tcp_connect", 0)?;
            info!("Attached kprobe to tcp_connect");

            let udp_program: &mut KProbe = ebpf.program_mut("udp_sendmsg").unwrap().try_into()?;
            udp_program.load()?;
            udp_program.attach("udp_sendmsg", 0)?;
            info!("Attached kprobe to udp_sendmsg");

            // Memory monitoring
            let ptrace_program: &mut TracePoint =
                ebpf.program_mut("sys_enter_ptrace").unwrap().try_into()?;
            ptrace_program.load()?;
            ptrace_program.attach("syscalls", "sys_enter_ptrace")?;
            info!("Attached tracepoint to sys_enter_ptrace");

            let vm_program: &mut TracePoint = ebpf
                .program_mut("sys_enter_process_vm_readv")
                .unwrap()
                .try_into()?;
            vm_program.load()?;
            vm_program.attach("syscalls", "sys_enter_process_vm_readv")?;
            info!("Attached tracepoint to sys_enter_process_vm_readv");
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported probe type: {}",
                args.probe_type
            ));
        }
    }

    // Get the appropriate perf event arrays based on probe type
    let mut event_arrays = Vec::new();

    match args.probe_type.as_str() {
        "vfs_read" | "sys_enter_read" => {
            let file_array = PerfEventArray::try_from(ebpf.take_map("FILE_READ_EVENTS").unwrap())?;
            event_arrays.push(("file", file_array));
        }
        "file_monitor" => {
            let secret_array =
                PerfEventArray::try_from(ebpf.take_map("SECRET_ACCESS_EVENTS").unwrap())?;
            event_arrays.push(("secret", secret_array));
        }
        "network_monitor" => {
            let network_array = PerfEventArray::try_from(ebpf.take_map("NETWORK_EVENTS").unwrap())?;
            event_arrays.push(("network", network_array));
        }
        "memory_monitor" => {
            let memory_array =
                PerfEventArray::try_from(ebpf.take_map("PROCESS_MEMORY_EVENTS").unwrap())?;
            event_arrays.push(("memory", memory_array));

            // Also get environment access events
            let env_array = PerfEventArray::try_from(ebpf.take_map("ENV_ACCESS_EVENTS").unwrap())?;
            event_arrays.push(("env", env_array));
        }
        "all" => {
            // Get all event arrays
            if let Some(Ok(file_array)) = ebpf
                .take_map("FILE_READ_EVENTS")
                .map(PerfEventArray::try_from)
            {
                event_arrays.push(("file", file_array));
            }
            if let Some(Ok(secret_array)) = ebpf
                .take_map("SECRET_ACCESS_EVENTS")
                .map(PerfEventArray::try_from)
            {
                event_arrays.push(("secret", secret_array));
            }
            if let Some(Ok(network_array)) = ebpf
                .take_map("NETWORK_EVENTS")
                .map(PerfEventArray::try_from)
            {
                event_arrays.push(("network", network_array));
            }
            if let Some(Ok(memory_array)) = ebpf
                .take_map("PROCESS_MEMORY_EVENTS")
                .map(PerfEventArray::try_from)
            {
                event_arrays.push(("memory", memory_array));
            }
            if let Some(Ok(env_array)) = ebpf
                .take_map("ENV_ACCESS_EVENTS")
                .map(PerfEventArray::try_from)
            {
                event_arrays.push(("env", env_array));
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown probe type for event arrays"));
        }
    }

    let monitor_mode = if args.security_mode
        || !matches!(args.probe_type.as_str(), "vfs_read" | "sys_enter_read")
    {
        "security monitoring"
    } else {
        "file reading monitor"
    };

    println!("🐝 bee-trace {} started", monitor_mode);
    println!("Probe type: {}", args.probe_type);
    if let Some(cmd_filter) = &args.command {
        println!("Filtering by command: {}", cmd_filter);
    }
    if let Some(duration) = args.duration {
        println!("Running for {} seconds", duration);
    }
    println!("Press Ctrl+C to exit\n");

    // Print header using formatter
    let formatter = EventFormatter::new(args.verbose);
    if args.security_mode || !matches!(args.probe_type.as_str(), "vfs_read" | "sys_enter_read") {
        println!("{}", formatter.header());
        println!("{}", formatter.separator());
    } else {
        println!("{}", formatter.legacy_header());
        println!("{}", formatter.legacy_separator());
    }

    // Create the event processing future
    let args_clone = args.clone();
    let event_processor = async move {
        let cpus = match online_cpus() {
            Ok(cpus) => cpus,
            Err(e) => {
                warn!("Failed to get online CPUs: {:?}", e);
                return;
            }
        };

        // Spawn tasks for each event array type
        for (event_type, mut perf_array) in event_arrays {
            for cpu_id in &cpus {
                let mut buf = match perf_array.open(*cpu_id, None) {
                    Ok(buf) => buf,
                    Err(e) => {
                        warn!(
                            "Failed to open perf buffer for CPU {} ({}): {}",
                            cpu_id, event_type, e
                        );
                        continue;
                    }
                };

                let args_for_task = args_clone.clone();
                let formatter_for_task = EventFormatter::new(args_for_task.verbose);
                let event_type = event_type.to_string();

                tokio::spawn(async move {
                    let mut buffers = (0..10)
                        .map(|_| BytesMut::with_capacity(1024))
                        .collect::<Vec<_>>();

                    loop {
                        let events = buf.read_events(&mut buffers);
                        match events {
                            Ok(events) => {
                                for buf in buffers.iter().take(events.read) {
                                    match event_type.as_str() {
                                        "file" => {
                                            let event = unsafe {
                                                buf.as_ptr()
                                                    .cast::<FileReadEvent>()
                                                    .read_unaligned()
                                            };
                                            process_legacy_event(
                                                &event,
                                                &args_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        "secret" => {
                                            let event = unsafe {
                                                buf.as_ptr()
                                                    .cast::<SecretAccessEvent>()
                                                    .read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::SecretAccess(event),
                                                &args_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        "network" => {
                                            let event = unsafe {
                                                buf.as_ptr().cast::<NetworkEvent>().read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::Network(event),
                                                &args_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        "memory" => {
                                            let event = unsafe {
                                                buf.as_ptr()
                                                    .cast::<ProcessMemoryEvent>()
                                                    .read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::ProcessMemory(event),
                                                &args_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        "env" => {
                                            let event = unsafe {
                                                buf.as_ptr()
                                                    .cast::<SecretAccessEvent>()
                                                    .read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::SecretAccess(event),
                                                &args_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        _ => {
                                            warn!("Unknown event type: {}", event_type);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Error reading perf events ({}): {}", event_type, e);
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                });
            }
        }

        // Keep the main task alive
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    // Handle duration or wait for Ctrl+C
    if let Some(duration) = args.duration {
        match timeout(Duration::from_secs(duration), event_processor).await {
            Ok(_) => {}
            Err(_) => println!("\nTracing completed after {} seconds", duration),
        }
    } else {
        tokio::select! {
            _ = event_processor => {},
            _ = signal::ctrl_c() => {
                println!("\nReceived Ctrl+C, exiting...");
            }
        }
    }

    Ok(())
}

fn process_legacy_event(event: &FileReadEvent, args: &Args, formatter: &EventFormatter) {
    // Apply filters
    if !args.should_filter_event(event) {
        return;
    }

    if !args.should_show_event(event) {
        return;
    }

    println!("{}", formatter.format_event(event));
}

fn process_security_event(
    event: &bee_trace::SecurityEvent,
    args: &Args,
    formatter: &EventFormatter,
) {
    // Apply filters
    if !args.should_filter_security_event(event) {
        return;
    }

    if !args.should_show_security_event(event) {
        return;
    }

    println!("{}", formatter.format_security_event(event));
}
