# Builds the guest agent as a static musl binary.
#
# The guest runs inside a microVM with no dynamic loader, so the binary has to be
# statically linked against musl. A container is the reliable way to get that
# toolchain without asking the host to install one; this image builds it from the
# repository itself so the binary and the source cannot drift apart.
FROM debian:bookworm-slim

ARG RUST_VERSION=1.90.0
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl musl-tools pkg-config \
 && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION" \
 && rustup target add x86_64-unknown-linux-musl

WORKDIR /src
# The dependency graph is resolved before the sources are copied, so a source
# edit does not re-download the world.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY guest guest
COPY scripts scripts

RUN CARGO_INCREMENTAL=0 \
    cargo build --release -p aiec-guest --target x86_64-unknown-linux-musl \
 && cp /src/target/x86_64-unknown-linux-musl/release/aiec-guest /out-aiec-guest