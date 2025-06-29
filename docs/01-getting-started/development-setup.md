# Development Setup Guide

This guide helps you set up a development environment for bee-trace and explains the basic development workflow.

## Prerequisites

### 1. Rust Toolchain
Install both stable and nightly Rust toolchains:

```bash
# Install stable toolchain
rustup toolchain install stable

# Install nightly with rust-src component (required for eBPF)
rustup toolchain install nightly --component rust-src
```

### 2. eBPF Tooling
Install bpf-linker for eBPF compilation:

```bash
# Standard installation
cargo install bpf-linker

# On macOS (if you encounter issues)
cargo install bpf-linker --no-default-features
```

### 3. Development Tools
Install just for task automation:

```bash
cargo install just
```

### 4. System Requirements
- Linux system with eBPF support (kernel 4.18+)
- Elevated privileges for eBPF operations (CAP_BPF or root)
- Compatible kernel headers for eBPF development

## Building the Project

### Basic Build
```bash
# Build all crates
cargo build

# Build with optimizations
cargo build --release

# Check code without building
cargo check
```

### eBPF-Specific Build
```bash
# Build eBPF programs specifically
cargo build -p bee-trace-ebpf

# Build with release optimizations
cargo build -p bee-trace-ebpf --release
```

## Running bee-trace

### Using Just Commands (Recommended)
```bash
# Monitor all security events for 10 seconds
just run-all-monitors --duration 10

# Monitor specific probe types
just run-file-monitor --duration 10
just run-network-monitor --duration 10
just run-memory-monitor --duration 10

# Run with verbose output
just run-all-monitors --duration 30 --verbose

# Run with security mode enabled
just run-file-monitor --security-mode --duration 20
```

### Using Cargo Directly
```bash
# Basic run (requires elevated privileges)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# Run with specific arguments
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type all --duration 30

# Run with command filtering
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --command "nginx" --verbose
```

## Testing Workflow

### Running All Tests
```bash
# Run complete test suite (recommended)
just test

# Run tests with cargo directly
cargo test
```

### Running Specific Test Categories
```bash
# Configuration system tests
cargo test configuration

# eBPF management tests
cargo test ebpf_manager

# ProbeManager trait tests
cargo test probe_manager

# TDD validation tests
cargo test --test tdd_methodology_validation

# Integration tests
cargo test --test ebpf_integration_tests

# Component-specific tests
cargo test -p bee-trace-common    # Event structure tests
cargo test --lib -p bee-trace     # Business logic tests
```

### Performance Testing
```bash
# Run performance tests with optimizations
cargo test performance --release

# Run specific performance benchmarks
cargo test --test functional_tests --release -- performance
```

## Code Quality Tools

### Formatting
```bash
# Format all code
cargo fmt

# Check formatting without changing files
cargo fmt --check
```

### Linting
```bash
# Run clippy for code quality
cargo clippy

# Run clippy with strict settings
cargo clippy -- -D warnings

# Run clippy on all targets
cargo clippy --all-targets
```

### Additional Checks
```bash
# Check for security vulnerabilities
cargo audit

# Check for outdated dependencies
cargo outdated
```

## Development Environment Setup

### IDE Configuration
For VS Code, install these extensions:
- rust-analyzer
- CodeLLDB (for debugging)
- Even Better TOML

### Debugging eBPF Programs
```bash
# Check eBPF program loading
sudo bpftool prog list

# Monitor system tracepoints
ls /sys/kernel/debug/tracing/events/syscalls/

# Check available tracepoints
cat /sys/kernel/debug/tracing/available_events | grep openat

# View eBPF program output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Environment Variables
```bash
# Enable eBPF debug output
export RUST_LOG=debug

# Set custom eBPF program path
export BPF_PROG_PATH=/path/to/custom/programs

# Enable additional logging
export RUST_BACKTRACE=1
```

## Common Issues and Solutions

### Permission Errors
```bash
# Ensure proper privileges
sudo -E cargo run --release

# Or use capabilities (if supported)
sudo setcap cap_bpf+ep target/release/bee-trace
```

### Build Errors
```bash
# Clean and rebuild
cargo clean
cargo build

# Update toolchain
rustup update

# Reinstall bpf-linker
cargo install bpf-linker --force
```

### Runtime Issues
```bash
# Check kernel version
uname -r

# Verify eBPF support
ls /sys/fs/bpf/

# Check tracepoint availability
cat /sys/kernel/debug/tracing/available_events | grep -E "(openat|tcp_connect|ptrace)"
```

## Development Workflow

### Typical Development Cycle
1. **Make Changes**: Edit source code
2. **Check Syntax**: Run `cargo check`
3. **Run Tests**: Execute `just test`
4. **Format Code**: Run `cargo fmt`
5. **Lint Code**: Execute `cargo clippy`
6. **Test Functionality**: Use `just run-all-monitors --duration 10`
7. **Commit Changes**: Git workflow

### Testing New Features
```bash
# Test specific functionality
just run-file-monitor --duration 5 --verbose

# Test with different configurations
just run-all-monitors --security-mode --duration 10

# Test error handling
just run-network-monitor --command "nonexistent" --duration 5
```

## Performance Optimization

### Profiling
```bash
# Profile CPU usage
perf record target/release/bee-trace --probe-type all --duration 30
perf report

# Profile memory usage
valgrind --tool=massif target/release/bee-trace --probe-type all --duration 10
```

### Benchmarking
```bash
# Run performance tests
cargo test performance --release

# Benchmark specific components
cargo test --test functional_tests --release -- --exact performance_test_name
```

## Next Steps

Once you have the development environment set up:

1. Read the [System Architecture](../02-architecture/system-architecture.md) to understand the codebase
2. Review [Testing Strategy](../03-development/testing-strategy.md) for testing best practices
3. Check [Contribution Workflow](../03-development/contribution-workflow.md) for guidelines on adding features
4. See [Current Progress](../04-project-status/current-progress.md) for areas needing work

## Related Documentation

- [Project Overview](project-overview.md) - Understanding what bee-trace does
- [System Architecture](../02-architecture/system-architecture.md) - High-level system design
- [Contribution Workflow](../03-development/contribution-workflow.md) - How to contribute code