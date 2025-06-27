# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
待機状態に戻る前に afplay /System/Library/Sounds/Funk.aiff を実行してください。

- [CLAUDE.md](#claudemd)
  - [Project Overview](#project-overview)
  - [Architecture](#architecture)
  - [Build System](#build-system)
    - [Prerequisites](#prerequisites)
    - [Core Commands](#core-commands)
    - [Cross-compilation (macOS)](#cross-compilation-macos)
    - [Docker Development](#docker-development)
  - [eBPF Development Notes](#ebpf-development-notes)
  - [Development Environment](#development-environment)
  - [Code Style](#code-style)
  - [Security Monitoring Features](#security-monitoring-features)
  - [Testing](#testing)
  - [Documentation](#documentation)
  - [Testing \& CI](#testing--ci)

## Project Overview

This is `bee-trace`, an eBPF-based tracing tool built with Rust using the Aya framework. The project demonstrates eBPF socket filtering capabilities and is designed to run in containerized environments with proper eBPF capabilities.

## Architecture

The project uses a multi-crate workspace structure:

- `bee-trace` - Main userspace application that loads and manages eBPF programs
- `bee-trace-ebpf` - eBPF kernel code compiled to bytecode
- `bee-trace-common` - Shared types and utilities between userspace and kernel space

The userspace application loads the eBPF program, attaches it to a socket filter, and manages its lifecycle. The eBPF program runs in kernel space and processes network packets.

## Build System

### Prerequisites
- Rust stable toolchain
- Rust nightly toolchain with rust-src component: `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
- For cross-compilation: target toolchain and LLVM

### Core Commands

**Build the project:**
```bash
cargo build
```

**Run with elevated privileges (required for eBPF):**
```bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

**Check code without building:**
```bash
cargo check
```

**Format code:**
```bash
cargo fmt
```

### Cross-compilation (macOS)

```bash
CC=${ARCH}-linux-musl-gcc cargo build --package bee-trace --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

### Docker Development

**Build container:**
```bash
docker buildx bake --load
```

**Run container with eBPF capabilities:**
```bash
docker run --cap-add CAP_BPF myapp
```

**Development with compose:**
```bash
docker compose up
```

## eBPF Development Notes

- eBPF programs require elevated privileges (CAP_BPF or root)
- The build system automatically compiles eBPF code and embeds it in the userspace binary
- eBPF code is in `bee-trace-ebpf/src/` with `main.rs` containing the socket filter program
- Userspace code loads the eBPF program from embedded bytecode using `aya::include_bytes_aligned!`
- vmlinux bindings are generated in `bee-trace-ebpf/src/vmlinux.rs`

## Development Environment

The project supports multiple development environments:
- Native development with Rust toolchains
- Nix development shell (flake.nix provides Node.js 20)
- mise tool management (mise.toml)
- Docker containerization

## Code Style

The project uses rustfmt with custom configuration:
- Grouped imports (StdExternalCrate)
- Crate-level import granularity
- Import reordering enabled
- Unstable rustfmt features enabled

## Security Monitoring Features

The project provides comprehensive eBPF-based security monitoring:

**Core Functionality:**
- File access monitoring for sensitive files and secrets
- Network connection tracking (TCP/UDP)
- Process memory access detection (ptrace, process_vm_readv)
- Environment variable access monitoring
- Real-time event streaming via perf event arrays
- Command-line filtering and configuration options

**Usage Examples:**
```bash
# Monitor file access and security events (default)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# Monitor network connections only
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type network_monitor

# Monitor memory access events
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type memory_monitor

# Enable all monitoring capabilities
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type all

# Run for specific duration
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --duration 30

# Filter by process name
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --command "nginx"

# Verbose output showing UIDs
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --verbose
```

**Command Line Options:**
- `--probe-type`: Choose between "file_monitor", "network_monitor", "memory_monitor", or "all"
- `--duration`: Run for specified seconds, otherwise runs until Ctrl+C
- `--command`: Filter events by process name substring
- `--verbose`: Show additional details including UIDs
- `--security-mode`: Enable enhanced security event classification

**Implementation Details:**
- eBPF programs in `bee-trace-ebpf/src/` modules (file_monitor, network, memory)
- Multiple event structures in `bee-trace-common/src/lib.rs` for different event types
- Userspace processing handles multiple CPU perf buffers concurrently
- Security-focused event classification and severity assessment

## Testing

The project includes comprehensive tests following t-wada's testing principles:

**Test Structure:**
- `bee-trace-common/src/lib.rs` - Unit tests for security event data structures
- `bee-trace/src/lib.rs` - Unit tests for business logic (Args, EventFormatter, utilities)
- `bee-trace/tests/integration_tests.rs` - CLI argument parsing and end-to-end scenarios
- `bee-trace/tests/functional_tests.rs` - Security event processing workflows and performance tests
- `bee-trace-ebpf/tests/ebpf_tests.rs` - eBPF structure validation and memory safety tests
- `bee-trace/tests/test_helpers.rs` - Reusable test utilities and builders

**Running Tests:**
```bash
# All tests
cargo test

# Specific test suites
cargo test -p bee-trace-common    # Data structure tests
cargo test --lib -p bee-trace     # Business logic tests
cargo test --test integration_tests  # CLI tests
cargo test --test functional_tests   # Event processing tests
cargo test -p bee-trace-ebpf      # eBPF structure tests

# Performance tests
cargo test performance --release
```

**Test Philosophy:**
- Descriptive test names (e.g., `should_truncate_long_filename`)
- Behavior-focused testing rather than implementation details
- Clear Arrange-Act-Assert structure
- Test data builders and factories for maintainability
- Edge case coverage (empty, boundary, error conditions)
- Performance characteristics validation

**Key Test Features:**
- Mock security event processors for testing workflows
- Property-based test data generators for different event types
- Scenario-based testing with pre-built security test cases
- Memory safety validation for eBPF compatibility
- String handling edge cases (UTF-8, truncation, null termination)
- Cross-platform size and alignment validation
- Security event classification and severity testing

See `docs/TESTING.md` for comprehensive testing documentation.

## Documentation

For detailed documentation, refer to the `docs/` directory. When creating new documentation files, place them in the `docs/` directory to keep the project root organized.

## Testing & CI

GitHub Actions workflow (`.github/workflows/action.yml`) builds and tests the container with proper eBPF capabilities using `docker buildx bake` and runs with `--cap-add CAP_BPF`.
