use std::time::Duration;

use aya::{maps::PerfEventArray, util::online_cpus, Ebpf};
use aya_log::EbpfLogger;
use bee_trace::{
    configuration::Configuration, ebpf_manager::EbpfApplication, Args, EventFormatter,
};
use bee_trace_common::{NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};
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

    // Convert Args to new Configuration system
    let config = convert_args_to_configuration(&args)?;

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

    // Create and configure the eBPF application
    let mut app = EbpfApplication::new(config);

    // Attach configured probes using the new architecture
    app.attach_configured_probes(&mut ebpf)
        .map_err(|e| anyhow::anyhow!("Failed to attach probes: {}", e))?;

    info!("✅ All configured probes attached successfully");
    let summary = app.get_probe_summary();
    info!(
        "📊 Attached {} probe types: {:?}",
        summary.attached_probe_types, summary.probe_types
    );

    // Get the appropriate perf event arrays based on configuration
    let mut event_arrays = Vec::new();
    let config = app.config();

    // Initialize event arrays based on configured probe types
    for &probe_type in &config.monitoring.probe_types {
        match probe_type {
            bee_trace::errors::ProbeType::FileMonitor => {
                if let Some(Ok(secret_array)) = ebpf
                    .take_map("SECRET_ACCESS_EVENTS")
                    .map(PerfEventArray::try_from)
                {
                    event_arrays.push(("secret", secret_array));
                    info!("📡 Initialized SECRET_ACCESS_EVENTS for file monitoring");
                }
            }
            bee_trace::errors::ProbeType::NetworkMonitor => {
                if let Some(Ok(network_array)) = ebpf
                    .take_map("NETWORK_EVENTS")
                    .map(PerfEventArray::try_from)
                {
                    event_arrays.push(("network", network_array));
                    info!("📡 Initialized NETWORK_EVENTS for network monitoring");
                }
            }
            bee_trace::errors::ProbeType::MemoryMonitor => {
                if let Some(Ok(memory_array)) = ebpf
                    .take_map("PROCESS_MEMORY_EVENTS")
                    .map(PerfEventArray::try_from)
                {
                    event_arrays.push(("memory", memory_array));
                    info!("📡 Initialized PROCESS_MEMORY_EVENTS for memory monitoring");
                }
                // Also get environment access events for memory monitoring
                if let Some(Ok(env_array)) = ebpf
                    .take_map("ENV_ACCESS_EVENTS")
                    .map(PerfEventArray::try_from)
                {
                    event_arrays.push(("env", env_array));
                    info!("📡 Initialized ENV_ACCESS_EVENTS for environment monitoring");
                }
            }
        }
    }

    let monitor_mode = "security monitoring";

    println!("🐝 bee-trace {} started", monitor_mode);
    println!("Probe types: {}", config.probe_type_legacy());
    if let Some(cmd_filter) = config.command_filter() {
        println!("Filtering by command: {}", cmd_filter);
    }
    if let Some(duration_secs) = config.duration_secs() {
        println!("Running for {} seconds", duration_secs);
    }
    println!("Press Ctrl+C to exit\n");

    // Print header using formatter
    let formatter = EventFormatter::new(config.is_verbose());
    println!("{}", formatter.header());
    println!("{}", formatter.separator());

    // Create the event processing future
    let config_clone = config.clone();
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

                let config_for_task = config_clone.clone();
                let formatter_for_task = EventFormatter::new(config_for_task.is_verbose());
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
                                        "secret" => {
                                            let event = unsafe {
                                                buf.as_ptr()
                                                    .cast::<SecretAccessEvent>()
                                                    .read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::SecretAccess(event),
                                                &config_for_task,
                                                &formatter_for_task,
                                            );
                                        }
                                        "network" => {
                                            let event = unsafe {
                                                buf.as_ptr().cast::<NetworkEvent>().read_unaligned()
                                            };
                                            process_security_event(
                                                &bee_trace::SecurityEvent::Network(event),
                                                &config_for_task,
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
                                                &config_for_task,
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
                                                &config_for_task,
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
    if let Some(duration_secs) = config.duration_secs() {
        match timeout(Duration::from_secs(duration_secs), event_processor).await {
            Ok(_) => {}
            Err(_) => println!("\nTracing completed after {} seconds", duration_secs),
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

/// Convert legacy Args to new Configuration system
fn convert_args_to_configuration(args: &Args) -> anyhow::Result<Configuration> {
    let mut cli_args = vec![];

    // Convert probe type
    cli_args.push("--probe-type");
    cli_args.push(&args.probe_type);

    // Convert duration if present
    let duration_str;
    if let Some(duration) = args.duration {
        cli_args.push("--duration");
        duration_str = duration.to_string();
        cli_args.push(&duration_str);
    }

    // Convert command filter if present
    if let Some(ref command) = args.command {
        cli_args.push("--command");
        cli_args.push(command);
    }

    // Convert verbose flag
    if args.verbose {
        cli_args.push("--verbose");
    }

    // Convert security mode flag
    if args.security_mode {
        cli_args.push("--security-mode");
    }

    // Build configuration from CLI args
    let config = Configuration::builder()
        .from_cli_args(&cli_args)
        .map_err(|e| anyhow::anyhow!("Failed to convert args to configuration: {}", e))?
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build configuration: {}", e))?;

    Ok(config)
}

fn process_security_event(
    event: &bee_trace::SecurityEvent,
    config: &Configuration,
    formatter: &EventFormatter,
) {
    // Apply command filter
    if let Some(cmd_filter) = config.command_filter() {
        let comm = event.command_as_str();
        if !comm.contains(cmd_filter) {
            return;
        }
    }

    // In security mode, show all events
    // Otherwise, show all events (keeping original behavior)
    if config.is_security_mode() {
        println!("{}", formatter.format_security_event(event));
    }
}
