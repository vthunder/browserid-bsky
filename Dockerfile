# pds-bridge — build from the repo root. Deployed as a dokku app via
# `git:from-image` (see .github/workflows/deploy-bridge.yml).

# Stage 1: Build
FROM rust:1.93-bookworm AS builder

WORKDIR /build

# Manifests first for dependency-layer caching (browserid-* deps come from
# git and land in this cached layer too)
COPY Cargo.toml Cargo.lock ./
COPY pds-bridge/Cargo.toml pds-bridge/

RUN mkdir -p pds-bridge/src && \
    echo "pub fn dummy() {}" > pds-bridge/src/lib.rs && \
    echo "fn main() {}" > pds-bridge/src/main.rs && \
    cargo build --release --package pds-bridge && \
    rm -rf pds-bridge/src

COPY pds-bridge/src pds-bridge/src

RUN touch pds-bridge/src/lib.rs pds-bridge/src/main.rs && \
    cargo build --release --package pds-bridge

# Stage 2: Runtime
FROM debian:bookworm-slim

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
