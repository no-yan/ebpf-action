# Quick Start Guide

This guide gets you up and running with bee-trace in minutes. Follow these steps to start monitoring security events on your system.

## Prerequisites

Before starting, ensure you have:
- Linux system with eBPF support (kernel 4.18+)
- Rust toolchain installed
- Elevated privileges (sudo access)

## Installation

### 1. Clone and Build
```bash
# Clone the repository
git clone https://github.com/your-org/bee-trace.git
cd bee-trace

# Install Rust nightly with eBPF support
rustup toolchain install nightly --component rust-src

# Install eBPF tooling
cargo install bpf-linker

# Install task runner
cargo install just

# Build the project
cargo build --release
```

### 2. Verify Installation
```bash
# Run a quick test (requires sudo)
sudo -E just test

# Check if everything builds correctly
cargo check
```

## Basic Usage

### Monitor All Security Events
```bash
# Monitor all probe types for 30 seconds
sudo -E just run-all-monitors --duration 30

# Sample output:
# [SECURITY] FILE_READ: pid=1234 cmd=cat file=/etc/passwd
# [SECURITY] NETWORK: pid=5678 cmd=curl dest=1.2.3.4:443 proto=TCP
# [SECURITY] PROC_MEMORY: pid=9012 cmd=strace target=1234 syscall=ptrace
```

### Monitor Specific Event Types

#### File Access Monitoring
```bash
# Monitor file access events
sudo -E just run-file-monitor --duration 20 --verbose

# Example events detected:
# - SSH key access: /home/user/.ssh/id_rsa
# - Certificate access: /etc/ssl/private/cert.key
# - Configuration files: /etc/passwd, /etc/shadow
```

#### Network Connection Monitoring
```bash
# Monitor network connections
sudo -E just run-network-monitor --duration 20 --security-mode

# Example events detected:
# - Outbound HTTPS connections
# - Suspicious IP addresses
# - High-frequency connection patterns
```

#### Memory Access Monitoring
```bash
# Monitor process memory access
sudo -E just run-memory-monitor --duration 15 --verbose

# Example events detected:
# - ptrace() system calls
# - process_vm_readv() operations
# - Inter-process memory access
```

## Common Usage Patterns

### Development Workflow Monitoring
Monitor your development environment for security issues:

```bash
# Monitor while running tests
sudo -E just run-all-monitors --duration 60 &
MONITOR_PID=$!

# Run your development tasks
npm install
npm run build
cargo test

# Stop monitoring
kill $MONITOR_PID
```

### CI/CD Pipeline Integration
Monitor build processes for suspicious activity:

```bash
# Monitor build process
sudo -E cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- \
  --probe-type all \
  --duration 300 \
  --command "build" \
  --security-mode \
  --verbose > security-report.json

# Check the report
cat security-report.json | jq '.events[] | select(.severity == "high")'
```

### Focused Security Monitoring
Monitor specific processes or commands:

```bash
# Monitor only curl commands
sudo -E just run-network-monitor --command "curl" --duration 30

# Monitor file access by specific process
sudo -E just run-file-monitor --command "npm" --duration 60

# Monitor with enhanced security classification
sudo -E just run-all-monitors --security-mode --duration 45
```

## Configuration Examples

### Basic Configuration File
Create `.github/security.yml`:

```yaml
# Security monitoring configuration
network:
  blocked_ips: 
    - "1.2.3.4"
    - "malicious-server.com"
  blocked_domains:
    - "evil-domain.com"
    - "suspicious-site.net"

files:
  watch_read:
    - "**/*.pem"
    - "**/id_rsa*"
    - "**/*.key"
    - "**/credentials.json"
    - "**/.env"
  exclude_paths:
    - "/tmp/**"
    - "/var/cache/**"

memory:
  secret_env_patterns:
    - "SECRET_*"
    - "*_TOKEN"
    - "*_KEY"
    - "AWS_*"
```

### Using Configuration File
```bash
# Run with custom configuration
sudo -E cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- \
  --probe-type all \
  --config .github/security.yml \
  --duration 60 \
  --security-mode
```

## Understanding Output

### Event Format
Events are displayed in a structured format:

```
[TIMESTAMP] [SEVERITY] EVENT_TYPE: details
```

### Event Types
- **FILE_READ**: File access events
- **NETWORK**: Network connection events
- **PROC_MEMORY**: Process memory access events
- **SECRET_ACCESS**: Access to sensitive files or environment variables

### Severity Levels
- **HIGH**: Potential security threats (SSH key access, suspicious IPs)
- **MEDIUM**: Notable events requiring attention
- **LOW**: Normal activity with security relevance

### Example Output
```
[2024-06-29T10:30:15Z] [HIGH] SECRET_ACCESS: pid=1234 uid=1000 cmd=cat file=/home/user/.ssh/id_rsa
[2024-06-29T10:30:16Z] [MEDIUM] NETWORK: pid=5678 uid=1000 cmd=curl dest=api.github.com:443 proto=TCP
[2024-06-29T10:30:17Z] [HIGH] PROC_MEMORY: pid=9012 uid=0 cmd=strace target=1234 syscall=ptrace
```

## Output Formats

### JSON Output
```bash
# Generate JSON report
sudo -E just run-all-monitors --duration 30 --format json > report.json

# Process with jq
cat report.json | jq '.summary'
cat report.json | jq '.events[] | select(.severity == "high")'
```

### Markdown Report
```bash
# Generate Markdown summary
sudo -E just run-all-monitors --duration 60 --format markdown > security-report.md
```

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Error: Operation not permitted
# Solution: Run with proper privileges
sudo -E cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# Or use just commands (recommended)
sudo -E just run-all-monitors
```

#### No Events Detected
```bash
# If no events appear, generate some activity:
# Terminal 1: Start monitoring
sudo -E just run-file-monitor --duration 30 --verbose

# Terminal 2: Generate file access events
cat /etc/passwd
ls ~/.ssh/
touch /tmp/test-file
```

#### Build Errors
```bash
# Clean and rebuild
cargo clean
cargo build --release

# Ensure nightly toolchain
rustup toolchain install nightly --component rust-src
```

### Debug Mode
```bash
# Enable debug output
RUST_LOG=debug sudo -E just run-all-monitors --duration 10

# Check eBPF program loading
sudo bpftool prog list | grep bee_trace
```

## Performance Monitoring

### Check System Impact
```bash
# Monitor CPU usage
top -p $(pgrep bee-trace)

# Monitor memory usage
ps aux | grep bee-trace

# Check event processing rate
sudo -E just run-all-monitors --duration 10 --verbose | wc -l
```

### Optimize Performance
```bash
# Use release build for production
cargo build --release

# Run with minimal verbosity
sudo -E just run-all-monitors --duration 60 > /dev/null

# Monitor specific probe types only
sudo -E just run-file-monitor --duration 60
```

## Integration Examples

### GitHub Actions Workflow
```yaml
name: Security Monitoring
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install bee-trace
        run: |
          # Installation steps
          
      - name: Run Security Monitoring
        run: |
          sudo -E ./bee-trace --probe-type all --security-mode --duration 300 > security-report.json
          
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### Docker Integration
```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy bee-trace binary
COPY target/release/bee-trace /usr/local/bin/

# Run with proper capabilities
CMD ["bee-trace", "--probe-type", "all", "--duration", "300"]
```

```bash
# Run container with eBPF capabilities
docker run --cap-add CAP_BPF --cap-add CAP_SYS_ADMIN bee-trace
```

## Next Steps

Now that you have bee-trace running:

1. **Explore Configuration**: Learn about [configuration options](../04-project-status/feature-specifications.md)
2. **Understand Architecture**: Read the [system architecture](../02-architecture/system-architecture.md)
3. **Contribute**: Follow the [contribution workflow](../03-development/contribution-workflow.md)
4. **Advanced Usage**: Check [testing strategy](../03-development/testing-strategy.md) for development

## Getting Help

If you encounter issues:
- Check the [troubleshooting section](development-setup.md#common-issues-and-solutions) in development setup
- Review [current progress](../04-project-status/current-progress.md) for known issues
- Examine test files for usage examples
- Read [component reference](../02-architecture/component-reference.md) for detailed information

## Security Considerations

### Best Practices
- Always run with minimal required privileges
- Regularly review security reports for anomalies
- Configure appropriate file and network patterns
- Monitor system performance impact

### Privacy Notes
- bee-trace never collects secret contents, only access metadata
- All sensitive data is filtered before logging
- Configuration allows excluding specific paths and patterns
- Event data includes process context but not content

Happy monitoring! 🔒