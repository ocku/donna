FROM rust:bookworm AS builder

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY config config
COPY crates crates
COPY vendor vendor

RUN cargo build --locked --release --bin donna

COPY examples/interop/Cargo.toml examples/interop/Cargo.lock examples/interop/
COPY examples/interop/src examples/interop/src
COPY examples/authority examples/authority
COPY examples/clients examples/clients
COPY examples/recursive examples/recursive
COPY examples/updates examples/updates
COPY examples/adapters/memory examples/adapters/memory
COPY examples/interop/fixtures/basic/zone.db examples/interop/fixtures/basic/zone.db

RUN cargo build --locked --release \
    --manifest-path examples/interop/Cargo.toml \
    --bin client \
    --bin external_backends \
    --bin iterative_client \
    --bin listeners \
    --bin recursive \
    --bin updates \
    --bin validate_denial

FROM debian:bookworm-slim

COPY --from=builder \
    /source/target/release/donna \
    /source/examples/interop/target/release/client \
    /source/examples/interop/target/release/external_backends \
    /source/examples/interop/target/release/iterative_client \
    /source/examples/interop/target/release/listeners \
    /source/examples/interop/target/release/recursive \
    /source/examples/interop/target/release/updates \
    /source/examples/interop/target/release/validate_denial \
    /usr/local/bin/

COPY examples/interop/fixtures/basic/recursive.toml \
    examples/interop/fixtures/basic/zone.db \
    /suite/fixtures/basic/

ENV CERT_DIR=/certs \
    ZONE_FILE=/suite/fixtures/basic/zone.db

CMD ["listeners"]
