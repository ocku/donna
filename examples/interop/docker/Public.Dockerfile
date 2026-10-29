FROM rust:bookworm AS builder

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY config config
COPY crates crates
COPY vendor vendor

RUN cargo build --locked --release --bin donna

FROM debian:bookworm-slim

COPY --from=builder /source/target/release/donna /usr/local/bin/donna

ENTRYPOINT ["donna"]
