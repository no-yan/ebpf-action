use std::time::Duration;

use aya::{
    maps::PerfEventArray,
    programs::{KProbe, TracePoint},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bee_trace::{Args, EventFormatter};
use bee_trace_common::FileReadEvent;
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

    // Attach the appropriate probe based on user selection
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
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported probe type: {}",
                args.probe_type
            ));
        }
    }

    // Get the perf event array
    let mut perf_array = PerfEventArray::try_from(ebpf.take_map("FILE_READ_EVENTS").unwrap())?;

    println!("🐝 bee-trace file reading monitor started");
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
    println!("{}", formatter.header());
    println!("{}", formatter.separator());

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

        for cpu_id in cpus {
            let mut buf = match perf_array.open(cpu_id, None) {
                Ok(buf) => buf,
                Err(e) => {
                    warn!("Failed to open perf buffer for CPU {}: {}", cpu_id, e);
                    continue;
                }
            };

            let args_for_task = args_clone.clone();
            let formatter_for_task = EventFormatter::new(args_for_task.verbose);
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers);
                    match events {
                        Ok(events) => {
                            for buf in buffers.iter().take(events.read) {
                                let event = unsafe {
                                    buf.as_ptr().cast::<FileReadEvent>().read_unaligned()
                                };
                                process_event(&event, &args_for_task, &formatter_for_task);
                            }
                        }
                        Err(e) => {
                            warn!("Error reading perf events: {}", e);
                        }
                    }
                    tokio::task::yield_now().await;
                }
            });
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

fn process_event(event: &FileReadEvent, args: &Args, formatter: &EventFormatter) {
    // Apply filters
    if !args.should_filter_event(event) {
        return;
    }

    if !args.should_show_event(event) {
        return;
    }

    println!("{}", formatter.format_event(event));
}
