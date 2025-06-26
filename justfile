default:
    @just --list

build:
    cargo build

build-release:
    cargo build --release

check:
    cargo check

fmt:
    cargo +nightly fmt

test:
    cargo test

# Run application with elevated privileges (required for eBPF)
run *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- {{args}}

run-vfs *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type vfs_read {{args}}

run-syscall *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type sys_enter_read {{args}}

# Run with duration limit
run-duration seconds *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --duration {{seconds}} {{args}}

# Run with command filter
run-filter command *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --command "{{command}}" {{args}}

run-verbose *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --verbose {{args}}

setup:
    rustup toolchain install nightly --component rust-src
    cargo install bpf-linker

# Performance monitoring example
monitor-cat:
    just run-filter "cat" --duration 10 --verbose
