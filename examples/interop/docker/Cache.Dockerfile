FROM rust:bookworm AS builder

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY crates crates
COPY vendor vendor

COPY examples/interop/Cargo.toml examples/interop/Cargo.lock examples/interop/
COPY examples/interop/src examples/interop/src
COPY examples/authority examples/authority
COPY examples/clients examples/clients
COPY examples/recursive examples/recursive
COPY examples/updates examples/updates
COPY examples/adapters/memory examples/adapters/memory

RUN cargo build --locked --release \
    --manifest-path examples/interop/Cargo.toml \
    --bin cache_bench

FROM debian:bookworm-slim

COPY --from=builder \
    /source/examples/interop/target/release/cache_bench \
    /usr/local/bin/cache_bench

ENTRYPOINT ["cache_bench"]
