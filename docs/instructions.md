# Development Instructions for bee-trace

This document provides guidance for developers working on the `bee-trace` project. It outlines the project's architecture, development workflow, and coding conventions.

## Project Overview

`bee-trace` is an eBPF-based security monitoring tool for GitHub Actions. It uses eBPF to monitor file access, network activity, and memory operations to detect and prevent supply chain attacks.

## Architecture

The project is a Rust workspace with the following crates:

-   **`bee-trace`**: The main userspace application that provides the CLI, loads and manages the eBPF programs, and processes events from the kernel.
-   **`bee-trace-ebpf`**: The eBPF programs that run in the kernel to monitor system activity.
-   **`bee-trace-common`**: Shared data structures (e.g., for events) used by both the userspace and eBPF code.
-   **`bee-trace-bindings`**: Bindings to kernel data structures.

## Development Workflow

1.  **Prerequisites:** Ensure you have the Rust toolchain (stable and nightly), `bpf-linker`, and `libbpf` installed.
2.  **Making Changes:**
    *   **Userspace:** For changes to the CLI, configuration, or event processing, modify the code in the `bee-trace` crate.
    *   **eBPF:** For changes to the kernel-level monitoring, modify the code in the `bee-trace-ebpf` crate.
    *   **Shared Data:** If you need to change the data that is passed from the kernel to userspace, modify the structs in the `bee-trace-common` crate.
3.  **Building:** Build the project using `cargo build`.
4.  **Running:** Run the application with `sudo -E cargo run --release`.
5.  **Testing:** Run the test suite with `cargo test`.

## Coding Conventions

*   **Rust:** Follow standard Rust conventions and `rustfmt`.
*   **eBPF:**
    *   Keep eBPF programs as simple as possible. Offload complex logic to the userspace application.
    *   Be mindful of the 512-byte stack limit in eBPF programs.
    *   Use `bpf_probe_read_user_str_bytes` to safely read strings from userspace.
    *   Use maps to share data between eBPF programs and between the kernel and userspace.
*   **Error Handling:** Use `anyhow` for error handling in the userspace application.
*   **Logging:** Use the `log` crate for logging in the userspace application.

## Key Areas for Future Development

*   **Configuration:** Enhance the configuration options for the security policies. For example, allow users to specify custom patterns for sensitive files.
*   **Network Monitoring:** Improve the network monitoring capabilities by parsing the full socket address to get the destination IP and port, and by adding support for IPv6.
*   **LSM Integration:** Implement the `socket_connect` LSM hook to allow for blocking of malicious network connections.
*   **Performance:** Optimize the event processing pipeline to handle high event rates.
*   **Data Enrichment:** Enrich the data sent from the eBPF programs to userspace. For example, resolve process and user IDs to their names.

## Testing

The project has a comprehensive test suite. When adding new features, please add corresponding tests.

*   **Unit Tests:** For testing individual functions and structs.
*   **Integration Tests:** For testing the CLI and the interaction between the userspace and eBPF code.
*   **Functional Tests:** For testing the end-to-end functionality of the tool.

Run all tests with `cargo test`.