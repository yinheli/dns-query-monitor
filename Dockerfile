FROM rust:1-slim AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y libpcap0.8 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/dns-query-monitor /usr/local/bin/

ENTRYPOINT ["dns-query-monitor"]
