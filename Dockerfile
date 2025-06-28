# syntax=docker/dockerfile:1

################################################################################
# Create a stage for building the application.

ARG RUST_VERSION=1.87.0
ARG APP_NAME=bee-trace
FROM rust:${RUST_VERSION}-slim-bullseye AS build
ARG APP_NAME
WORKDIR /app

# Build the application.
# Leverage a cache mount to /usr/local/cargo/registry/
# for downloaded dependencies and a cache mount to /app/target/ for
# compiled dependencies which will speed up subsequent builds.
# Leverage a bind mount to the src directory to avoid having to copy the
# source code into the container. Once built, copy the executable to an
# output directory before the cache mounted /app/target is unmounted.
RUN --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y
RUN rustup install stable
RUN rustup toolchain install nightly --component rust-src && \
    cargo install bpf-linker
RUN --mount=type=bind,source=bee-trace,target=bee-trace \
    --mount=type=bind,source=bee-trace-common,target=bee-trace-common \
    --mount=type=bind,source=bee-trace-ebpf,target=bee-trace-ebpf \
    --mount=type=bind,source=bee-trace-bindings,target=bee-trace-bindings \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
RUST_BACKTRACE=1 cargo build --release
cp ./target/release/$APP_NAME /bin/myapp
EOF

################################################################################
FROM debian:bullseye-slim AS final

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
## FIXME: 非特権コンテナで実行する
## see: https://man7.org/linux/man-pages/man7/capabilities.7.html
# RUN adduser \
#     --disabled-password \
#     --gecos "" \
#     --home "/nonexistent" \
#     --shell "/sbin/nologin" \
#     --no-create-home \
#     --uid "${UID}" \
#     appuser
# USER appuser

# Copy the executable from the "build" stage.
COPY --from=build /bin/myapp /bin/

# Expose the port that the application listens on.
EXPOSE 1000

# What the container should run when it is started.
CMD ["/bin/myapp"]
