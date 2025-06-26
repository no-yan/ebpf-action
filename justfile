default:
    @just --list

# Build commands
build:
    cargo +nightly build

build-release:
    cargo +nightly build --release

check:
    cargo +nightly check

fmt:
    cargo +nightly fmt

test:
    cargo test

# Setup development environment
setup:
    rustup toolchain install nightly --component rust-src
    cargo install bpf-linker

# Basic run commands - Default to security monitoring mode
run *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --security-mode {{args}}

run-verbose *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --security-mode --verbose {{args}}

# Legacy file monitoring modes (backward compatibility)
run-vfs *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type vfs_read {{args}}

run-syscall *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type sys_enter_read {{args}}

# Security monitoring modes
run-file-monitor *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type file_monitor --security-mode {{args}}

run-network-monitor *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type network_monitor --security-mode {{args}}

run-memory-monitor *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type memory_monitor --security-mode {{args}}

run-all-monitors *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --probe-type all --security-mode {{args}}

# Utility commands
run-duration seconds *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --duration {{seconds}} --security-mode {{args}}

run-filter command *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --command "{{command}}" --security-mode {{args}}

run-with-config config_path *args:
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --config {{config_path}} --security-mode {{args}}

# Docker commands
docker-build:
    docker buildx bake --load

docker-run:
    docker run --cap-add CAP_BPF myapp

docker-compose:
    docker compose up

# Demo and testing scenarios
demo-file-access:
    @echo "🔍 Demonstrating file access monitoring..."
    just run-file-monitor --duration 30 --verbose

demo-network-monitor:
    @echo "🌐 Demonstrating network monitoring..."
    just run-network-monitor --duration 30 --verbose

demo-memory-monitor:
    @echo "🧠 Demonstrating memory access monitoring..."
    just run-memory-monitor --duration 30 --verbose

demo-comprehensive:
    @echo "🛡️  Demonstrating comprehensive security monitoring..."
    just run-all-monitors --duration 60 --verbose

# Performance monitoring examples
monitor-cat:
    just run-filter "cat" --duration 10 --verbose

monitor-secrets:
    @echo "🔐 Monitoring for secret file access..."
    just run-file-monitor --duration 30 --verbose

monitor-network-activity:
    @echo "🌐 Monitoring network connections..."
    just run-network-monitor --duration 30

# Development and testing
test-security:
    cargo test -p bee-trace-common
    cargo test --lib -p bee-trace
    cargo test --test integration_tests
    cargo test --test functional_tests

test-ebpf:
    cargo test -p bee-trace-ebpf

lint:
    cargo clippy

# Configuration examples
create-security-config:
    @echo "📋 Creating example security configuration..."
    @mkdir -p .github
    @cp .github/security.yml .github/security-example.yml || echo "Security config already exists"

# Git hooks and development workflow
setup-hooks:
    lefthook install
    @echo "✅ Git hooks installed successfully"
    @echo "Pre-commit hooks will run: format check, lint, test, build"
    @echo "Pre-push hooks will run: release build, security audit"

# Clean commands
clean:
    cargo clean

clean-all: clean
    docker system prune -f
