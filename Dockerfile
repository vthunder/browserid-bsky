# pds-bridge — build from the repo root. Deployed as a dokku app via
# `git:from-image` (see .github/workflows/deploy-bridge.yml).

# Stage 1: Build
# Pinned by digest; the tag names the exact rustc the digest carries, and
# .github/workflows/release-candidate.yml checks the CI toolchain, this tag
# and the digest's RUST_VERSION all agree.
FROM rust:1.93.1-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /build

# Manifests first for dependency-layer caching (browserid-* deps come from
# git and land in this cached layer too)
COPY Cargo.toml Cargo.lock ./
COPY pds-bridge/Cargo.toml pds-bridge/
COPY smoke/Cargo.toml smoke/

RUN mkdir -p pds-bridge/src smoke/src && \
    echo "pub fn dummy() {}" > pds-bridge/src/lib.rs && \
    echo "fn main() {}" > pds-bridge/src/main.rs && \
    echo "fn main() {}" > smoke/src/main.rs && \
    cargo build --release --package pds-bridge && \
    rm -rf pds-bridge/src smoke/src

COPY pds-bridge/src pds-bridge/src

# smoke is a workspace member but not shipped — restore a dummy target so
# the workspace resolves.
RUN mkdir -p smoke/src && echo "fn main() {}" > smoke/src/main.rs && \
    touch pds-bridge/src/lib.rs pds-bridge/src/main.rs && \
    cargo build --release --package pds-bridge

# Stage 2: Runtime
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/pds-bridge /app/

RUN mkdir -p /data

ENV BRIDGE_PORT=5000
ENV BRIDGE_DB=/data/pds-bridge.db

EXPOSE 5000

CMD ["/app/pds-bridge"]
