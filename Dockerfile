FROM rust:1.84 AS builder

WORKDIR /usr/src/pacman

COPY Cargo.toml Cargo.lock ./

COPY . .

RUN cargo build --release --bin encrypted_server

FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pacman

COPY --from=builder /usr/src/pacman/target/release/encrypted_server /usr/local/bin/encrypted_server

EXPOSE 8080

# Run the encrypted_server binary
CMD ["encrypted_server"]
