FROM rust:1.84 AS builder

WORKDIR /usr/src/pacman

COPY Cargo.toml Cargo.lock ./

COPY . .

RUN cargo build --release --bin encryption_server --bin encryption_client

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

COPY --from=builder /usr/src/pacman/target/release/encryption_server .
COPY --from=builder /usr/src/pacman/target/release/encryption_client .

EXPOSE 3000

# Default to running the server, but can be overridden with --entrypoint
CMD ["encryption_server"]
