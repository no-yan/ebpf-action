# bee-trace Documentation

Welcome to the comprehensive documentation for bee-trace, an eBPF-based security monitoring tool. This documentation is systematically organized to support different users and use cases.

## 📚 Documentation Organization

The documentation follows a logical progression from basic understanding to advanced development:

### 01. Getting Started
Essential information for first-time users and quick setup:

- **[Project Overview](01-getting-started/project-overview.md)** - What is bee-trace and why use it?
- **[Development Setup](01-getting-started/development-setup.md)** - Environment setup and build instructions
- **[Quick Start Guide](01-getting-started/quick-start-guide.md)** - Basic usage examples and common patterns

### 02. Architecture
System design and technical principles:

- **[System Architecture](02-architecture/system-architecture.md)** - High-level architectural overview and design philosophy
- **[Component Reference](02-architecture/component-reference.md)** - Detailed breakdown of individual components
- **[Design Principles](02-architecture/design-principles.md)** - TDD methodology and architectural patterns

### 03. Development
Practical guidance for contributors and developers:

- **[Testing Strategy](03-development/testing-strategy.md)** - Comprehensive testing approach and best practices
- **[Contribution Workflow](03-development/contribution-workflow.md)** - How to contribute code and follow development patterns

### 04. Project Status
Current state and planning information:

- **[Feature Specifications](04-project-status/feature-specifications.md)** - Detailed requirements and implementation status
- **[Development Roadmap](04-project-status/development-roadmap.md)** - Strategic long-term development plan
- **[Architecture Refactoring](04-project-status/rearchitecture.md)** - Ongoing architectural improvements and technical debt resolution

### 05. Technical Details
Deep technical implementation specifics:

- **[Configuration Migration](05-technical-details/configuration-migration.md)** - Config system unification technical details

## 🚀 Quick Navigation

### New to bee-trace?
1. Start with [Project Overview](01-getting-started/project-overview.md) to understand what bee-trace does
2. Follow [Development Setup](01-getting-started/development-setup.md) to get your environment ready
3. Try [Quick Start Guide](01-getting-started/quick-start-guide.md) for hands-on experience

### Want to understand the system?
1. Read [System Architecture](02-architecture/system-architecture.md) for the big picture
2. Dive into [Component Reference](02-architecture/component-reference.md) for detailed technical information
3. Learn about [Design Principles](02-architecture/design-principles.md) and methodology

### Ready to contribute?
1. Review [Testing Strategy](03-development/testing-strategy.md) to understand our testing approach
2. Follow [Contribution Workflow](03-development/contribution-workflow.md) for development guidelines
3. Check [Architecture Refactoring](04-project-status/rearchitecture.md) for ongoing improvements

### Managing the project?
1. Review [Feature Specifications](04-project-status/feature-specifications.md) for requirements status
2. Track progress with [Development Roadmap](04-project-status/development-roadmap.md)
3. Monitor architectural work in [Architecture Refactoring](04-project-status/rearchitecture.md)

## 🎯 Key Features Overview

### Security Monitoring Capabilities
- **File Access Monitoring**: SSH keys, credentials, certificates
- **Network Connection Tracking**: TCP/UDP with blocking capabilities  
- **Memory Access Detection**: Inter-process communication and ptrace monitoring
- **Real-time Processing**: Low-latency event classification

### Technical Excellence
- **Modern Architecture**: Loose coupling and high cohesion design
- **Comprehensive Testing**: 112+ tests with mock implementations
- **Performance Optimized**: <5% CPU overhead, kernel-space filtering
- **Developer Experience**: Clear documentation and examples

## 📊 Current Project Status

### Implementation Progress
- ✅ **Core Features**: All monitoring capabilities implemented
- ✅ **Architecture**: Modular design with trait-based abstractions
- ✅ **Testing**: Comprehensive test coverage across all components
- ✅ **Documentation**: Systematic organization with clear navigation

### Active Development Focus
- **Event Processing Enhancement**: Extracting monolithic async processing (Phase 5)
- **Reporting System**: Advanced security event classification
- **Performance Optimization**: Production deployment readiness

## 🏗️ Architecture Highlights

bee-trace demonstrates modern software engineering principles applied to systems programming:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Args      │───▶│  Configuration  │───▶│ EbpfApplication │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ ProbeManager    │◀───│ UnifiedProbe    │◀───│   aya::Ebpf     │
│ (Interface)     │    │ Manager         │    └─────────────────┘
└─────────────────┘    └─────────────────┘
        △                       │
        │                       ▼
┌───────┴───────┬─────────────────┬─────────────────┐
│ FileProbe     │ NetworkProbe    │ MemoryProbe     │
│ Manager       │ Manager         │ Manager         │
└───────────────┴─────────────────┴─────────────────┘
```

### Key Design Principles
- **Loose Coupling**: Components can evolve independently
- **High Cohesion**: Single responsibility per module
- **Interface-Based**: Trait abstractions enable testing and flexibility
- **Deep Modules**: Complex eBPF operations hidden behind simple APIs

## 🛠️ Development Workflow Summary

### Prerequisites
- Rust stable and nightly toolchains
- eBPF toolchain (bpf-linker)
- Just task runner
- Linux with eBPF support

### Common Commands
```bash
# Build and test
just test
cargo build --release

# Run monitoring (requires sudo)
just run-all-monitors --duration 30
just run-file-monitor --security-mode

# Development quality checks
cargo fmt && cargo clippy
```

### Testing Categories
- **Unit Tests**: Component behavior validation (112+ tests)
- **Integration Tests**: Component interaction testing
- **Mock Tests**: External dependency isolation
- **Performance Tests**: Benchmarking and optimization

## 📈 Performance Characteristics

### Efficiency Metrics
- **CPU Overhead**: <5% under normal workload
- **Memory Usage**: <100MB for all probe types active
- **Event Processing**: Zero event loss under 1000 events/second
- **Latency Impact**: <10% increase for monitored operations

### Optimization Strategy
- Kernel-space filtering minimizes userspace overhead
- Per-CPU perf buffer processing prevents contention
- Efficient event structure layouts for memory optimization
- Async processing with backpressure handling

## 🔒 Security Features

### Monitoring Capabilities
- **File Access**: Detects access to sensitive files and credentials
- **Network Activity**: Monitors connections with configurable blocking
- **Memory Operations**: Tracks inter-process communication and ptrace
- **Environment Variables**: Monitors access to secret environment variables

### Security Best Practices
- Never collects secret contents, only access metadata
- Comprehensive input validation prevents injection attacks
- Type-safe error handling prevents information leaks
- Minimal privileges required (CAP_BPF)

## 🤝 Contributing

We welcome contributions! Here's how to get involved:

### For New Contributors
1. Read [Project Overview](01-getting-started/project-overview.md) to understand the project
2. Set up your environment with [Development Setup](01-getting-started/development-setup.md)
3. Try the [Quick Start Guide](01-getting-started/quick-start-guide.md) to get familiar
4. Review [Contribution Workflow](03-development/contribution-workflow.md) for guidelines

### For Experienced Developers
1. Check [Current Progress](04-project-status/current-progress.md) for priority work
2. Review [System Architecture](02-architecture/system-architecture.md) for technical context
3. Understand [Testing Strategy](03-development/testing-strategy.md) for our approach
4. Follow [Design Principles](02-architecture/design-principles.md) for consistency

### Areas Needing Help
- **Phase 5**: Event processing separation (high priority)
- **Performance**: Optimization and benchmarking
- **Documentation**: Examples and tutorials
- **Testing**: Additional edge case coverage

## 📚 Technology Stack

### Core Technologies
- **Rust**: Memory-safe systems programming
- **eBPF**: Kernel-space efficient monitoring
- **Aya Framework**: Rust eBPF development
- **Tokio**: Async runtime for event processing

### Development Tools
- **Just**: Task automation and build management
- **Cargo**: Package management and testing
- **bpf-linker**: eBPF program compilation
- **Comprehensive Mocking**: Testing without external dependencies

## 🔗 External Resources

### Learning eBPF
- [eBPF.io](https://ebpf.io/) - Official eBPF documentation
- [Aya Book](https://aya-rs.dev/) - Rust eBPF framework guide
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html) - Brendan Gregg's comprehensive guide

### Rust Development
- [The Rust Book](https://doc.rust-lang.org/book/) - Official Rust documentation
- [A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php) - Design principles we follow

## 📝 Documentation Maintenance

### Organization Principles
- **Sequential Numbering**: Folders numbered to suggest reading order
- **Purpose-Based Grouping**: Content organized by user intent
- **Consistent Naming**: All files use kebab-case naming
- **Single Responsibility**: Each document serves one clear purpose

### When to Update
- **Architecture Changes**: Update system and component documentation
- **New Features**: Update specifications and component reference
- **Process Changes**: Update contribution workflow and testing strategy
- **Progress Updates**: Keep current progress and roadmap current

### Cross-Reference Strategy
Each document includes relevant links to related content, creating a web of interconnected information that supports different user journeys through the documentation.

---

## 🆘 Need Help?

- **Getting Started Issues**: Check [Development Setup](01-getting-started/development-setup.md) troubleshooting
- **Architecture Questions**: Review [System Architecture](02-architecture/system-architecture.md) and [Component Reference](02-architecture/component-reference.md)
- **Development Problems**: See [Contribution Workflow](03-development/contribution-workflow.md) and [Testing Strategy](03-development/testing-strategy.md)
- **Project Status**: Check [Development Roadmap](04-project-status/development-roadmap.md) for priorities and [Architecture Refactoring](04-project-status/rearchitecture.md) for technical progress

**Welcome to bee-trace! Start your journey with the [Project Overview](01-getting-started/project-overview.md).** 🚀