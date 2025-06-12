FROM mcr.microsoft.com/devcontainers/rust:1-bullseye

RUN --mount=type=cache,target=/var/lib/apt/lists \
    --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y --no-install-recommends \
    gnupg2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Rust with nightly sources, BPF and aya tools
RUN rustup install stable && \
    rustup toolchain install nightly --component rust-src
RUN cargo install bpf-linker
