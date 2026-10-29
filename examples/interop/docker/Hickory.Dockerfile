# External implementation and clients: compiled and executed only in Docker.
FROM rust@sha256:e9da6f6c3ed5095fd5d33bf7cdf309830a178a8147888f1b2f76d5769bd9306c AS builder

ADD --checksum=sha256:af9cb60182bf95d752b59c9d818a2ac4b4cf7246a5b27960c22b919d2d8de4bb \
    https://codeload.github.com/hickory-dns/hickory-dns/tar.gz/bd37cafbdd86112a6da32878f8c9bab22e14377e \
    /tmp/hickory.tar.gz

RUN mkdir /source \
    && tar -xzf /tmp/hickory.tar.gz -C /source --strip-components=1

WORKDIR /source
RUN cargo build --locked --release --jobs 1 \
        --no-default-features \
        --package hickory-dns \
        --package hickory-util \
        --bin dns \
        --bin hickory-dns \
        --bin resolve \
        --features hickory-dns/dnssec-ring,hickory-dns/resolver,hickory-dns/recursor \
    && mkdir /identity \
    && sha256sum Cargo.lock > /identity/Cargo.lock.sha256

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/hickory-dns/hickory-dns" \
    org.opencontainers.image.revision="bd37cafbdd86112a6da32878f8c9bab22e14377e" \
    org.opencontainers.image.version="0.26.3"

COPY --from=builder \
    /source/target/release/dns \
    /source/target/release/hickory-dns \
    /source/target/release/resolve \
    /usr/local/bin/
COPY --from=builder /identity /identity
COPY --from=builder /source/Cargo.lock /identity/Cargo.lock

COPY examples/interop/fixtures/basic/hickory.toml /suite/hickory.toml
COPY examples/interop/fixtures/basic/zone.db /suite/fixtures/basic/zone.db

CMD ["hickory-dns", "--config", "/suite/hickory.toml", "--workers", "2", "--port", "53"]
