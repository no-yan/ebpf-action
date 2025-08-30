# bee-trace-exec-test

Integration test crate that exercises the `bee-trace` eBPF programs end to end.
The provided test loads and attaches the file-monitor program and verifies that
access to a `.env` file is reported through the perf buffer.

> **Note**
> The test requires root privileges to attach eBPF programs. When run without
> sufficient permission, it will skip automatically.
>
> ```bash
> cargo test -p bee-trace-exec-test -- --nocapture
> ```

