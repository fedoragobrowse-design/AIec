FROM debian:bookworm-slim

# Toolchain required by the acceptance harnesses:
#  - iproute2 / nftables / iptables: TAP + NAT for the Firecracker guest network
#  - openssl, curl, jq, ca-certificates: TLS material, API calls, JSON parsing
#  - build-essential, pkg-config, libssl-dev: cargo builds inside the container
#  - git: the guest image build script and harness tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 nftables iptables \
      openssl curl jq ca-certificates \
      build-essential pkg-config libssl-dev \
      git python3 procps postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENV CARGO_TERM_COLOR=never

# Rust toolchain for building the workspace inside the container.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path \
    && ln -s /usr/local/cargo/bin/rustc /usr/local/cargo/bin/cargo /usr/local/cargo/bin/rustfmt /usr/local/cargo/bin/cargo-clippy /usr/bin/ \
    && /usr/local/cargo/bin/rustup target add x86_64-unknown-linux-musl \
    && chmod -R a+rwX /usr/local/cargo /usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH
