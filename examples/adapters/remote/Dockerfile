ARG RUST_IMAGE=rust:bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

ENV CARGO_BUILD_JOBS=1
WORKDIR /source

# A caller may supply an SDK-warm builder; replace every project source tree.
RUN rm -rf \
    crates \
    examples/adapters/remote/src \
    src \
    vendor

COPY Cargo.toml Cargo.lock ./
COPY src src
COPY crates crates
COPY vendor vendor

COPY examples/adapters/remote/Cargo.toml \
    examples/adapters/remote/Cargo.lock \
    examples/adapters/remote/
COPY examples/adapters/remote/src examples/adapters/remote/src

# Rebuild project packages without discarding the warm SDK dependency cache.
RUN cargo clean --locked --release \
        --manifest-path examples/adapters/remote/Cargo.toml \
        --package dns \
        --package donna-remote-adapters-example \
        --package nameserver \
        --package resolver \
        --package transport \
    && cargo build --locked --release \
        --manifest-path examples/adapters/remote/Cargo.toml

FROM ${RUNTIME_IMAGE}

COPY --from=builder \
    /source/examples/adapters/remote/target/release/cache-engine \
    /usr/local/bin/cache-engine

ENTRYPOINT ["cache-engine"]
